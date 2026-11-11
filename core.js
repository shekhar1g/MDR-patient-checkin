/* MDR app-initiated pre-check-in: protocol core.
 * Plain script, no framework. Runs in a browser and in Node 18+ (globalThis.crypto).
 * Everything cryptographic here is real: AES-256-GCM JWE (SHL STU1), ES256 App Attestation
 * (KTC guide v0.10.2), ES384 client assertion (SMART Backend Services).
 */
(function (root) {
'use strict';

const te = new TextEncoder();
const td = new TextDecoder();

// ---------- base64url ----------
function b64u(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64uDecode(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64uJson(obj) { return b64u(te.encode(JSON.stringify(obj))); }
function randomBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
function uuid() { return crypto.randomUUID(); }
function nowIso() { return new Date().toISOString(); }

// ---------- JWE: alg "dir", enc "A256GCM", cty "application/fhir+json"  (SHL STU1 §Encrypting) ----------
const JWE_HEADER = { alg: 'dir', enc: 'A256GCM', cty: 'application/fhir+json' };
const JWE_HEADER_B64 = b64uJson(JWE_HEADER);

async function encryptJwe(obj, keyBytes) {
  const plaintext = te.encode(JSON.stringify(obj));
  const iv = randomBytes(12);                       // unique nonce per encryption
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const aad = te.encode(JWE_HEADER_B64);            // AAD = ASCII(BASE64URL(protected header))
  const out = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plaintext));
  const ct = out.slice(0, out.length - 16), tag = out.slice(out.length - 16);
  return [JWE_HEADER_B64, '', b64u(iv), b64u(ct), b64u(tag)].join('.');
}
async function decryptJwe(compact, keyBytes) {
  const [h, ek, iv, ct, tag] = compact.split('.');
  if (ek !== '') throw new Error('alg dir requires an empty encrypted key');
  const header = JSON.parse(td.decode(b64uDecode(h)));
  if (header.alg !== 'dir' || header.enc !== 'A256GCM') throw new Error('unexpected JWE header');
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const c = b64uDecode(ct), t = b64uDecode(tag);
  const joined = new Uint8Array(c.length + t.length); joined.set(c); joined.set(t, c.length);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64uDecode(iv), additionalData: te.encode(h), tagLength: 128 }, key, joined);
  return { header, payload: JSON.parse(td.decode(pt)) };
}

// ---------- JWS (compact) with ECDSA ----------
const CURVES = { ES256: { namedCurve: 'P-256', hash: 'SHA-256' }, ES384: { namedCurve: 'P-384', hash: 'SHA-384' } };
async function generateSigningKey(alg) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: CURVES[alg].namedCurve }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  delete jwk.key_ops; delete jwk.ext;
  const kid = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))))).slice(0, 16);
  return { alg, privateKey: kp.privateKey, publicJwk: { ...jwk, kid, use: 'sig', alg } };
}
async function signJwt(claims, keyPair, header = {}) {
  const alg = keyPair.alg;
  const h = { alg, kid: keyPair.publicJwk.kid, ...header };
  const input = b64uJson(h) + '.' + b64uJson(claims);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: CURVES[alg].hash }, keyPair.privateKey, te.encode(input)));
  return input + '.' + b64u(sig);
}
async function verifyJwt(jwt, jwks) {
  const [h, p, s] = jwt.split('.');
  const header = JSON.parse(td.decode(b64uDecode(h)));
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid);
  if (!jwk) return { ok: false, reason: 'kid ' + header.kid + ' not in JWKS', header };
  if (jwk.kty !== 'EC') return { ok: false, reason: 'key is not EC', header };
  const curve = CURVES[header.alg];
  if (!curve || jwk.crv !== curve.namedCurve) return { ok: false, reason: 'alg/curve mismatch', header };
  const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: jwk.crv }, false, ['verify']);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: curve.hash }, key, b64uDecode(s), te.encode(h + '.' + p));
  return { ok, reason: ok ? 'signature valid' : 'signature invalid', header, claims: JSON.parse(td.decode(b64uDecode(p))) };
}

// ---------- SMART Health Link payload (SHL STU1 §Payload) ----------
function buildShlink({ url, keyBytes, exp, flag, label }) {
  if (url.length > 128) throw new Error('SHL url SHALL NOT exceed 128 characters');
  if (flag && flag.includes('U') && flag.includes('P')) throw new Error('flag U SHALL NOT be used in combination with P');
  const payload = { url, flag, key: b64u(keyBytes), exp, label };
  if (!flag) delete payload.flag;
  if (label && label.length > 80) throw new Error('label SHALL be no longer than 80 characters');
  return { payload, uri: 'shlink:/' + b64uJson(payload) };
}
function parseShlink(uri) {
  const m = /shlink:\/([A-Za-z0-9_-]+)/.exec(uri);     // bare URI or viewer-prefixed URL; KTC says accept both
  if (!m) throw new Error('not a shlink');
  return JSON.parse(td.decode(b64uDecode(m[1])));
}

// ---------- Minimal PDF writer (text only, Helvetica) ----------
function textPdf(title, lines) {
  const esc = s => String(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  let y = 760;
  let content = 'BT /F1 14 Tf 50 ' + y + ' Td (' + esc(title) + ') Tj ET\n';
  y -= 26;
  for (const ln of lines) {
    if (y < 50) break;
    content += 'BT /F1 10 Tf 50 ' + y + ' Td (' + esc(ln) + ') Tj ET\n';
    y -= 14;
  }
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    '<< /Length ' + te.encode(content).length + ' >>\nstream\n' + content + 'endstream',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'
  ];
  let pdf = '%PDF-1.4\n%âãÏÓ\n';
  const offsets = [];
  objs.forEach((o, i) => { offsets.push(te.encode(pdf).length); pdf += (i + 1) + ' 0 obj\n' + o + '\nendobj\n'; });
  const xref = te.encode(pdf).length;
  pdf += 'xref\n0 ' + (objs.length + 1) + '\n0000000000 65535 f \n';
  for (const off of offsets) pdf += String(off).padStart(10, '0') + ' 00000 n \n';
  pdf += 'trailer\n<< /Size ' + (objs.length + 1) + ' /Root 1 0 R >>\nstartxref\n' + xref + '\n%%EOF\n';
  return te.encode(pdf);
}

// ---------- Sample longitudinal data held by the app (fictional patient) ----------
const PATIENT_ID = 'urn:uuid:7b1c2d7e-5a0f-4c3e-9b2a-1f6d8e9c0a11';
const patient = {
  resourceType: 'Patient', id: '7b1c2d7e-5a0f-4c3e-9b2a-1f6d8e9c0a11',
  identifier: [{ system: 'https://mydigirecords.com/fhir/patient-id', value: 'MDR-204117' }],
  name: [{ family: 'Alvarez', given: ['Jordan'] }], gender: 'female', birthDate: '1979-03-14',
  telecom: [{ system: 'phone', value: '913-555-0142', use: 'mobile' }],
  address: [{ line: ['4410 W 118th St'], city: 'Leawood', state: 'KS', postalCode: '66211' }]
};
const RECORDS = {
  allergies: { label: 'Allergies and intolerances', profile: 'US Core AllergyIntolerance', ktc: 'SHALL persist', resources: [
    { resourceType: 'AllergyIntolerance', id: 'al-1', clinicalStatus: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/allergyintolerance-clinical', code: 'active' }] }, verificationStatus: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/allergyintolerance-verification', code: 'confirmed' }] }, code: { coding: [{ system: 'http://www.nlm.nih.gov/research/umls/rxnorm', code: '7980', display: 'Penicillin G' }], text: 'Penicillin' }, patient: { reference: PATIENT_ID }, reaction: [{ manifestation: [{ text: 'Hives' }], severity: 'moderate' }] },
    { resourceType: 'AllergyIntolerance', id: 'al-2', clinicalStatus: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/allergyintolerance-clinical', code: 'active' }] }, code: { coding: [{ system: 'http://snomed.info/sct', code: '300913006', display: 'Shellfish allergy' }], text: 'Shellfish' }, patient: { reference: PATIENT_ID } }
  ] },
  medications: { label: 'Medications', profile: 'US Core MedicationRequest', ktc: 'SHALL persist', resources: [
    { resourceType: 'MedicationRequest', id: 'mr-1', status: 'active', intent: 'order', medicationCodeableConcept: { coding: [{ system: 'http://www.nlm.nih.gov/research/umls/rxnorm', code: '314076', display: 'lisinopril 10 MG Oral Tablet' }] }, subject: { reference: PATIENT_ID }, authoredOn: '2026-02-11', requester: { display: 'Dr. R. Okafor' }, dosageInstruction: [{ text: '1 tablet by mouth daily' }] },
    { resourceType: 'MedicationRequest', id: 'mr-2', status: 'active', intent: 'order', medicationCodeableConcept: { coding: [{ system: 'http://www.nlm.nih.gov/research/umls/rxnorm', code: '861007', display: 'metformin hydrochloride 500 MG Oral Tablet' }] }, subject: { reference: PATIENT_ID }, authoredOn: '2026-02-11', requester: { display: 'Dr. R. Okafor' }, dosageInstruction: [{ text: '1 tablet by mouth twice daily with meals' }] },
    { resourceType: 'MedicationRequest', id: 'mr-3', status: 'active', intent: 'order', medicationCodeableConcept: { coding: [{ system: 'http://www.nlm.nih.gov/research/umls/rxnorm', code: '617310', display: 'atorvastatin 20 MG Oral Tablet' }] }, subject: { reference: PATIENT_ID }, authoredOn: '2026-02-11', requester: { display: 'Dr. R. Okafor' }, dosageInstruction: [{ text: '1 tablet by mouth at bedtime' }] }
  ] },
  conditions: { label: 'Problems and health concerns', profile: 'US Core Condition', ktc: 'SHALL persist', resources: [
    { resourceType: 'Condition', id: 'c-1', clinicalStatus: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/condition-clinical', code: 'active' }] }, category: [{ coding: [{ system: 'http://terminology.hl7.org/CodeSystem/condition-category', code: 'problem-list-item' }] }], code: { coding: [{ system: 'http://snomed.info/sct', code: '44054006', display: 'Diabetes mellitus type 2' }] }, subject: { reference: PATIENT_ID }, onsetDateTime: '2019-06' },
    { resourceType: 'Condition', id: 'c-2', clinicalStatus: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/condition-clinical', code: 'active' }] }, category: [{ coding: [{ system: 'http://terminology.hl7.org/CodeSystem/condition-category', code: 'problem-list-item' }] }], code: { coding: [{ system: 'http://snomed.info/sct', code: '38341003', display: 'Hypertensive disorder' }] }, subject: { reference: PATIENT_ID }, onsetDateTime: '2017-01' },
    { resourceType: 'Condition', id: 'c-3', clinicalStatus: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/condition-clinical', code: 'active' }] }, category: [{ coding: [{ system: 'http://terminology.hl7.org/CodeSystem/condition-category', code: 'problem-list-item' }] }], code: { coding: [{ system: 'http://snomed.info/sct', code: '55822004', display: 'Hyperlipidemia' }] }, subject: { reference: PATIENT_ID } }
  ] },
  immunizations: { label: 'Immunizations', profile: 'US Core Immunization', ktc: 'SHALL persist', resources: [
    { resourceType: 'Immunization', id: 'im-1', status: 'completed', vaccineCode: { coding: [{ system: 'http://hl7.org/fhir/sid/cvx', code: '140', display: 'Influenza, seasonal, injectable, preservative free' }] }, patient: { reference: PATIENT_ID }, occurrenceDateTime: '2026-10-03', primarySource: true },
    { resourceType: 'Immunization', id: 'im-2', status: 'completed', vaccineCode: { coding: [{ system: 'http://hl7.org/fhir/sid/cvx', code: '115', display: 'Tdap' }] }, patient: { reference: PATIENT_ID }, occurrenceDateTime: '2021-08-19', primarySource: true }
  ] },
  vitals: { label: 'Vital signs (latest)', profile: 'US Core Vital Signs (Observation)', ktc: 'SHOULD persist', resources: [
    { resourceType: 'Observation', id: 'ob-bp', status: 'final', category: [{ coding: [{ system: 'http://terminology.hl7.org/CodeSystem/observation-category', code: 'vital-signs' }] }], code: { coding: [{ system: 'http://loinc.org', code: '85354-9', display: 'Blood pressure panel with all children optional' }] }, subject: { reference: PATIENT_ID }, effectiveDateTime: '2026-11-09T07:40:00-06:00', component: [
      { code: { coding: [{ system: 'http://loinc.org', code: '8480-6', display: 'Systolic blood pressure' }] }, valueQuantity: { value: 128, unit: 'mmHg', system: 'http://unitsofmeasure.org', code: 'mm[Hg]' } },
      { code: { coding: [{ system: 'http://loinc.org', code: '8462-4', display: 'Diastolic blood pressure' }] }, valueQuantity: { value: 82, unit: 'mmHg', system: 'http://unitsofmeasure.org', code: 'mm[Hg]' } } ] },
    { resourceType: 'Observation', id: 'ob-wt', status: 'final', category: [{ coding: [{ system: 'http://terminology.hl7.org/CodeSystem/observation-category', code: 'vital-signs' }] }], code: { coding: [{ system: 'http://loinc.org', code: '29463-7', display: 'Body weight' }] }, subject: { reference: PATIENT_ID }, effectiveDateTime: '2026-11-09T07:40:00-06:00', valueQuantity: { value: 84, unit: 'kg', system: 'http://unitsofmeasure.org', code: 'kg' } }
  ] },
  insurance: { label: 'Insurance card', profile: 'CARIN Digital Insurance Card Coverage', ktc: 'SHOULD persist', resources: [
    { resourceType: 'Coverage', id: 'cov-1', status: 'active', subscriberId: 'KSB-88213904', beneficiary: { reference: PATIENT_ID }, relationship: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/subscriber-relationship', code: 'self' }] }, payor: [{ display: 'Sunflower Health Plan' }], class: [{ type: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/coverage-class', code: 'group' }] }, value: 'GRP-55120', name: 'Employer PPO' }] }
  ] }
};

// ---------- Visit types: suggested records, with the clinical reason ----------
const VISITS = {
  primary: { label: 'Primary care, annual visit', specialty: 'Family medicine', suggest: {
    allergies: 'Needed before any prescription is written or renewed.',
    medications: 'Reconciliation against the chart is the first thing a PCP does.',
    conditions: 'Active problem list drives the visit agenda and screening orders.',
    immunizations: 'Annual visit is where gaps (flu, Tdap, pneumococcal) get closed.',
    vitals: 'Home blood pressure and weight trend between visits are more useful than one reading in clinic.',
    insurance: 'Front desk verifies eligibility before the visit.' } },
  ortho: { label: 'Orthopedics, knee pain', specialty: 'Orthopedic surgery', suggest: {
    allergies: 'Contrast, latex and NSAID reactions change imaging and injection plans.',
    medications: 'Anticoagulants and NSAIDs matter for injections and any surgery.',
    conditions: 'Diabetes affects wound healing and infection risk for procedures.',
    insurance: 'Imaging and procedures need eligibility and prior auth.' },
    off: { immunizations: 'Rarely needed for an ortho consult.', vitals: 'Clinic will take its own.' } },
  dental: { label: 'Dental, routine exam', specialty: 'General dentistry', suggest: {
    allergies: 'Local anesthetic, latex and antibiotic allergies are asked at every dental visit.',
    medications: 'Bisphosphonates and anticoagulants change what a dentist can do that day.',
    conditions: 'Diabetes and cardiac history drive periodontal care and antibiotic prophylaxis.',
    vitals: 'Dental offices screen blood pressure before anesthesia.',
    insurance: 'Dental benefit check at the desk.' },
    off: { immunizations: 'Not part of a dental intake.' } },
  eye: { label: 'Eye care, diabetic eye exam', specialty: 'Ophthalmology', suggest: {
    conditions: 'Diabetes duration sets the retinopathy screening interval.',
    medications: 'Steroids and hydroxychloroquine have eye effects the doctor checks for.',
    allergies: 'Dilating drop and iodine reactions.',
    vitals: 'Blood pressure matters for retinal vascular findings.',
    insurance: 'Medical vs vision benefit routing.' },
    off: { immunizations: 'Not needed for an eye exam.' } }
};
function recommend(visitKey) {
  const v = VISITS[visitKey];
  return Object.keys(RECORDS).map(k => ({ key: k, label: RECORDS[k].label, profile: RECORDS[k].profile, ktc: RECORDS[k].ktc,
    suggested: Boolean(v.suggest[k]), reason: v.suggest[k] || (v.off && v.off[k]) || 'Not suggested for this visit type.' }));
}

// ---------- Questionnaire + US Core 9.0.0 QuestionnaireResponse (SDC based) ----------
const QUESTIONNAIRES = {
  primary: { url: 'https://mydigirecords.com/fhir/Questionnaire/precheckin-primary-care', version: '1.0', items: [
    { linkId: 'reason', text: 'What is the main reason for this visit?', type: 'string', answer: 'Annual check-up; refill lisinopril' },
    { linkId: 'new-symptoms', text: 'Any new symptoms since your last visit?', type: 'string', answer: 'Occasional headaches in the afternoon' },
    { linkId: 'med-changes', text: 'Have you started, stopped, or changed any medicines?', type: 'boolean', answer: false },
    { linkId: 'tobacco', text: 'Do you currently use tobacco?', type: 'boolean', answer: false },
    { linkId: 'phq2', text: 'Over the past two weeks, how often have you felt down, depressed, or hopeless?', type: 'choice', answer: 'Not at all' } ] },
  ortho: { url: 'https://mydigirecords.com/fhir/Questionnaire/precheckin-orthopedics', version: '1.0', items: [
    { linkId: 'reason', text: 'Which joint, and what happened?', type: 'string', answer: 'Right knee, pain climbing stairs for 6 weeks, no injury' },
    { linkId: 'pain', text: 'Pain today, 0 to 10', type: 'integer', answer: 5 },
    { linkId: 'prior-imaging', text: 'Any X-ray or MRI of this joint already?', type: 'boolean', answer: false },
    { linkId: 'blood-thinner', text: 'Do you take a blood thinner?', type: 'boolean', answer: false } ] },
  dental: { url: 'https://mydigirecords.com/fhir/Questionnaire/precheckin-dental', version: '1.0', items: [
    { linkId: 'reason', text: 'Reason for visit', type: 'string', answer: 'Routine cleaning and exam' },
    { linkId: 'last-cleaning', text: 'When was your last cleaning?', type: 'date', answer: '2026-04-22' },
    { linkId: 'bleeding-gums', text: 'Do your gums bleed when you brush?', type: 'boolean', answer: true },
    { linkId: 'bisphosphonate', text: 'Have you ever taken a bone-strengthening medicine (bisphosphonate)?', type: 'boolean', answer: false } ] },
  eye: { url: 'https://mydigirecords.com/fhir/Questionnaire/precheckin-eye', version: '1.0', items: [
    { linkId: 'reason', text: 'Reason for visit', type: 'string', answer: 'Yearly diabetic eye exam' },
    { linkId: 'vision-change', text: 'Any change in vision, floaters, or flashes?', type: 'boolean', answer: false },
    { linkId: 'driver', text: 'Will someone drive you home after dilation?', type: 'boolean', answer: true },
    { linkId: 'last-a1c', text: 'Most recent A1c, if you know it', type: 'string', answer: '6.9% (Sept 2026)' } ] }
};
function buildQuestionnaire(visitKey) {
  const q = QUESTIONNAIRES[visitKey];
  return { resourceType: 'Questionnaire', url: q.url, version: q.version, status: 'active', title: VISITS[visitKey].label + ' pre-visit intake',
    item: q.items.map(i => ({ linkId: i.linkId, text: i.text, type: i.type })) };
}
function buildQuestionnaireResponse(visitKey, answers) {
  const q = QUESTIONNAIRES[visitKey];
  const val = (type, a) => type === 'boolean' ? { valueBoolean: a } : type === 'integer' ? { valueInteger: a } : type === 'date' ? { valueDate: a } : type === 'choice' ? { valueCoding: { display: a } } : { valueString: a };
  return { resourceType: 'QuestionnaireResponse', id: 'qr-' + visitKey,
    questionnaire: q.url + '|' + q.version,                 // SDC: canonical of the form being answered (required)
    status: 'completed', subject: { reference: PATIENT_ID }, authored: nowIso(),
    author: { reference: PATIENT_ID }, source: { reference: PATIENT_ID },   // US Core: author/source carry USCDI provenance author
    item: q.items.map(i => ({ linkId: i.linkId, text: i.text, answer: [val(i.type, answers[i.linkId] !== undefined ? answers[i.linkId] : i.answer)] })) };
}

// ---------- Provenance with identity assurance (MDR proposal; not defined in any published IG) ----------
const IAL_EXT = 'https://mydigirecords.com/fhir/StructureDefinition/identity-assurance';
function buildProvenance(idv) {
  return { resourceType: 'Provenance', id: 'prov-idv',
    target: [{ reference: PATIENT_ID }], recorded: idv.verifiedAt,
    activity: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/v3-DataOperation', code: 'CREATE' }] },
    agent: [
      { type: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/provenance-participant-type', code: 'author' }] }, who: { reference: PATIENT_ID } },
      { type: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/provenance-participant-type', code: 'verifier' }] }, who: { display: idv.csp },
        extension: [{ url: IAL_EXT, extension: [
          { url: 'level', valueCode: idv.ial },                       // NIST SP 800-63-3 IAL label; no HL7 code system exists for this today
          { url: 'credentialServiceProvider', valueString: idv.csp },
          { url: 'verifiedAt', valueDateTime: idv.verifiedAt },
          { url: 'verifiedAttributes', valueString: 'name, birthDate, address' } ] }] } ] };
}

// ---------- PatientSharedDocumentReference (KTC guide profile) ----------
function buildPdfDocRef(pdfBytes, kind) {
  const type = kind === 'rendered' ? { system: 'http://loinc.org', code: '60591-5', display: 'Patient summary Document' }
                                   : { system: 'http://loinc.org', code: '51855-5', display: 'Patient Note' };
  return { resourceType: 'DocumentReference', id: 'doc-' + kind,
    meta: { security: [{ system: 'http://terminology.hl7.org/CodeSystem/v3-ObservationValue', code: 'PATAST', display: 'patient asserted' }] },
    status: 'current', type: { coding: [type] },
    category: [{ coding: [{ system: 'https://cms.gov/fhir/CodeSystem/patient-shared-category', code: 'patient-shared', display: 'Patient-Shared' }] }],
    subject: { reference: PATIENT_ID }, author: [{ reference: PATIENT_ID }], date: nowIso(),
    description: kind === 'rendered' ? 'FHIR-Rendered PDF of this bundle' : 'Patient story',
    content: [{ attachment: { contentType: 'application/pdf', data: b64u(pdfBytes).replace(/-/g, '+').replace(/_/g, '/') } }] };
}

// ---------- App Attestation (KTC guide, optional): ES256 JWS in Bundle.meta.extension ----------
const ATTESTATION_EXT = 'https://cms.gov/fhir/StructureDefinition/app-attestation';
async function buildAttestation(appKey, iss) {
  // Exactly three claims are defined: iss, iat, jti. No exp; the SHLink's exp governs lifetime.
  return signJwt({ iss, iat: Math.floor(Date.now() / 1000), jti: uuid() }, appKey);
}

// ---------- PatientSharedBundle ----------
function renderLines(selected, qr) {
  const lines = ['Patient: Jordan Alvarez, DOB 1979-03-14', 'Shared by the patient from the MyDigiRecords app on ' + new Date().toUTCString(), ''];
  for (const k of selected) {
    lines.push(RECORDS[k].label.toUpperCase());
    for (const r of RECORDS[k].resources) {
      const name = (r.code && (r.code.text || r.code.coding[0].display)) || (r.medicationCodeableConcept && r.medicationCodeableConcept.coding[0].display) || (r.vaccineCode && r.vaccineCode.coding[0].display) || (r.payor && r.payor[0].display) || r.resourceType;
      const extra = r.dosageInstruction ? ' - ' + r.dosageInstruction[0].text : r.occurrenceDateTime ? ' - ' + r.occurrenceDateTime : r.component ? ' - ' + r.component.map(c => c.valueQuantity.value).join('/') + ' mmHg' : r.valueQuantity ? ' - ' + r.valueQuantity.value + ' ' + r.valueQuantity.unit : '';
      lines.push('  ' + name + extra);
    }
    lines.push('');
  }
  if (qr) { lines.push('INTAKE ANSWERS'); for (const it of qr.item) { const a = it.answer[0]; lines.push('  ' + it.text + ' ' + String(Object.values(a)[0].display || Object.values(a)[0])); } }
  return lines;
}
async function buildBundle({ selected, visitKey, answers, idv, appKey, appIss, includePdf = true }) {
  const qr = buildQuestionnaireResponse(visitKey, answers || {});
  const entries = [{ fullUrl: PATIENT_ID, resource: patient }];
  for (const k of selected) for (const r of RECORDS[k].resources) entries.push({ fullUrl: 'urn:uuid:' + uuid(), resource: r });
  entries.push({ fullUrl: 'urn:uuid:' + uuid(), resource: qr });
  entries.push({ fullUrl: 'urn:uuid:' + uuid(), resource: buildProvenance(idv) });
  let pdf = null;
  if (includePdf) { pdf = textPdf('Pre-visit summary (patient shared)', renderLines(selected, qr)); entries.push({ fullUrl: 'urn:uuid:' + uuid(), resource: buildPdfDocRef(pdf, 'rendered') }); }
  const attestation = await buildAttestation(appKey, appIss);
  const bundle = { resourceType: 'Bundle', meta: { extension: [{ url: ATTESTATION_EXT, valueString: attestation }] },
    type: 'collection', timestamp: nowIso(), entry: entries };   // no meta.profile: the guide says SHOULD NOT include it
  return { bundle, questionnaireResponse: qr, pdf, attestation };
}

// ---------- Simulated patient-app server (hosts encrypted files, serves U and P links, audits) ----------
function createAppServer(origin) {
  const files = new Map(); const audit = [];
  return {
    origin, audit,
    async host(bundle, { flag, exp, label, passcode }) {
      const keyBytes = randomBytes(32);
      const jwe = await encryptJwe(bundle, keyBytes);
      const id = b64u(randomBytes(32));                   // 256 bits of entropy in the path
      const rec = { id, jwe, exp, flag, attemptsLeft: passcode ? 3 : null, passcodeHash: passcode ? await sha256(passcode) : null, active: true };
      files.set(id, rec);
      const url = origin + '/shl/' + id;
      const link = buildShlink({ url, keyBytes, exp, flag, label });
      return { id, link, keyBytes, jwe };
    },
    // KTC route: U flag. GET {url}?recipient=... -> application/jose. No auth, CORS *.
    directGet(id, recipient) {
      const f = files.get(id);
      if (!f || !f.active) return { status: 404 };
      if (!recipient) return { status: 400, body: { error: 'recipient is required' } };
      if (f.exp && f.exp < Math.floor(Date.now() / 1000)) return { status: 404, body: { error: 'expired' } };
      audit.push({ at: nowIso(), id, recipient, via: 'GET (U flag)' });
      return { status: 200, headers: { 'content-type': 'application/jose', 'access-control-allow-origin': '*' }, body: f.jwe };
    },
    // Base SHL route: P flag. POST {url} {recipient, passcode, embeddedLengthMax} -> manifest.
    async manifest(id, body) {
      const f = files.get(id);
      if (!f || !f.active) return { status: 404 };
      if (!body || !body.recipient) return { status: 400, body: { error: 'recipient is required' } };
      if (f.passcodeHash) {
        if (!body.passcode || (await sha256(body.passcode)) !== f.passcodeHash) {
          f.attemptsLeft -= 1; if (f.attemptsLeft <= 0) f.active = false;
          return { status: 401, body: { remainingAttempts: Math.max(0, f.attemptsLeft) } };
        }
      }
      audit.push({ at: nowIso(), id, recipient: body.recipient, via: 'POST manifest (P flag)' });
      return { status: 200, headers: { 'content-type': 'application/json' }, body: { status: 'finalized', files: [{ contentType: 'application/fhir+json', embedded: f.jwe }] } };
    },
    revoke(id) { const f = files.get(id); if (f) f.active = false; }
  };
}
async function sha256(s) { return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(s)))); }

// ---------- Simulated EHR (receiver): capability, token endpoint, ingestion, chart ----------
function createEhr({ name, base, clientRegistry, trustedApps, mpi, appointments, supportsOperation = true }) {
  const chart = { intake: [], reconciliation: [], documents: [], provenanceFlags: [] };
  const capability = { resourceType: 'CapabilityStatement', status: 'active', date: '2026-11-01', kind: 'instance', fhirVersion: '4.0.1', format: ['json'],
    implementation: { description: name, url: base },
    rest: [{ mode: 'server',
      security: { service: [{ coding: [{ system: 'http://terminology.hl7.org/CodeSystem/restful-security-service', code: 'SMART-on-FHIR' }] }],
        extension: [{ url: 'http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris', extension: [{ url: 'token', valueUri: base + '/oauth2/token' }, { url: 'authorize', valueUri: base + '/oauth2/authorize' }] }] },
      resource: [
        { type: 'DocumentReference', interaction: [{ code: 'create' }, { code: 'read' }, { code: 'search-type' }], supportedProfile: ['http://hl7.org/fhir/us/core/StructureDefinition/us-core-documentreference'] },
        { type: 'Appointment', interaction: [{ code: 'read' }, { code: 'search-type' }] },
        { type: 'Patient', interaction: [{ code: 'read' }, { code: 'search-type' }] } ],
      operation: supportsOperation ? [{ name: 'receive-shl', definition: 'https://mydigirecords.com/fhir/OperationDefinition/receive-shl' }] : [] }] };
  const issuedTokens = new Map();
  async function fetchJwks(iss) {           // in the demo, apps publish their JWKS in-memory at {iss}/.well-known/jwks.json
    const app = trustedApps.get(iss); return app ? app.jwks : null;
  }
  async function resolveShlink(uri, passcode, recipient, appServer) {
    const p = parseShlink(uri);
    if (p.exp && p.exp < Math.floor(Date.now() / 1000)) throw new Error('SHLink expired');
    const id = p.url.split('/shl/')[1];
    const keyBytes = b64uDecode(p.key);
    let jwe;
    if ((p.flag || '').includes('P')) {
      const r = await appServer.manifest(id, { recipient, passcode, embeddedLengthMax: 1048576 });
      if (r.status === 401) throw new Error('passcode rejected, remainingAttempts=' + r.body.remainingAttempts);
      if (r.status !== 200) throw new Error('manifest HTTP ' + r.status);
      jwe = r.body.files[0].embedded;
    } else {
      const r = appServer.directGet(id, recipient);
      if (r.status !== 200) throw new Error('GET HTTP ' + r.status);
      jwe = r.body;
    }
    const { payload } = await decryptJwe(jwe, keyBytes);
    return payload;
  }
  async function verifyAttestation(bundle) {
    const ext = ((bundle.meta || {}).extension || []).find(e => e.url === ATTESTATION_EXT);
    if (!ext) return { present: false, ok: false, label: 'no attestation (processing continues)' };
    const [, p] = ext.valueString.split('.');
    const claims = JSON.parse(td.decode(b64uDecode(p)));
    if (!trustedApps.has(claims.iss)) return { present: true, ok: false, label: 'issuer not in trust framework app list (processing continues)', claims };
    const jwks = await fetchJwks(claims.iss);
    const v = await verifyJwt(ext.valueString, jwks);
    return { present: true, ok: v.ok, label: v.ok ? 'recognized app: ' + claims.iss : 'signature failed (processing continues)', claims, header: v.header };
  }
  function matchPatient(pt) {
    const dob = pt.birthDate, fam = pt.name[0].family.toLowerCase(), giv = pt.name[0].given[0].toLowerCase();
    const hit = mpi.find(m => m.birthDate === dob && m.family.toLowerCase() === fam && m.given.toLowerCase() === giv);
    return hit ? { matched: true, mrn: hit.mrn, score: 'exact on name + DOB' } : { matched: false };
  }
  function checkIal(bundle) {
    const prov = bundle.entry.map(e => e.resource).find(r => r.resourceType === 'Provenance' && r.target.some(t => t.reference === PATIENT_ID));
    if (!prov) return { present: false };
    const agent = prov.agent.find(a => (a.extension || []).some(x => x.url === IAL_EXT));
    if (!agent) return { present: true, ial: null };
    const ext = agent.extension.find(x => x.url === IAL_EXT);
    const get = n => (ext.extension.find(x => x.url === n) || {});
    return { present: true, ial: get('level').valueCode, csp: get('credentialServiceProvider').valueString, verifiedAt: get('verifiedAt').valueDateTime };
  }
  async function file(bundle, ctx) {
    const resources = bundle.entry.map(e => e.resource);
    const att = await verifyAttestation(bundle);
    const pt = resources.find(r => r.resourceType === 'Patient');
    const match = matchPatient(pt);
    const ial = checkIal(bundle);
    const appt = ctx.appointmentId ? appointments.find(a => a.id === ctx.appointmentId) : null;
    const filed = { mustPersist: [], shouldPersist: [], intake: [], documents: [], ignored: [] };
    for (const r of resources) {
      if (r.resourceType === 'Patient' || r.resourceType === 'Provenance') continue;
      if (['Condition', 'MedicationRequest', 'AllergyIntolerance', 'Immunization'].includes(r.resourceType)) { filed.mustPersist.push(r); chart.reconciliation.push({ resource: r, status: 'pending clinician review', source: 'patient-shared' }); }
      else if (r.resourceType === 'QuestionnaireResponse') { filed.intake.push(r); chart.intake.push({ resource: r, encounter: appt ? appt.encounterId : null }); }
      else if (r.resourceType === 'DocumentReference') { filed.documents.push(r); chart.documents.push({ resource: r, encounter: appt ? appt.encounterId : null }); }
      else { filed.shouldPersist.push(r); chart.reconciliation.push({ resource: r, status: 'pending clinician review', source: 'patient-shared' }); }
    }
    chart.provenanceFlags.push({ at: nowIso(), attestation: att.label, identity: ial.ial ? ial.ial + ' via ' + ial.csp : 'none asserted', match, encounter: appt ? appt.encounterId : 'unbound (walk-in queue)' });
    return { attestation: att, match, ial, appointment: appt, filed };
  }
  return {
    name, base, capability, chart,
    async token(form, appJwksByClientId) {
      // SMART Backend Services: grant_type=client_credentials + JWT client assertion (RFC 7523), verified against the client's registered JWKS
      if (form.grant_type !== 'client_credentials') return { status: 400, body: { error: 'unsupported_grant_type' } };
      if (form.client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') return { status: 400, body: { error: 'invalid_client' } };
      const [, p] = form.client_assertion.split('.');
      const claims = JSON.parse(td.decode(b64uDecode(p)));
      const reg = clientRegistry.get(claims.iss);
      if (!reg || claims.sub !== claims.iss) return { status: 401, body: { error: 'invalid_client', error_description: 'unknown client_id' } };
      if (claims.aud !== base + '/oauth2/token') return { status: 401, body: { error: 'invalid_client', error_description: 'aud must be the token endpoint' } };
      if (claims.exp > Math.floor(Date.now() / 1000) + 300) return { status: 401, body: { error: 'invalid_client', error_description: 'exp more than 5 minutes ahead' } };
      const v = await verifyJwt(form.client_assertion, reg.jwks);
      if (!v.ok) return { status: 401, body: { error: 'invalid_client', error_description: v.reason } };
      const requested = form.scope.split(' ');
      const granted = requested.filter(s => reg.scopes.includes(s));
      if (!granted.length) return { status: 400, body: { error: 'invalid_scope' } };
      const token = 'ehr_' + b64u(randomBytes(24));
      issuedTokens.set(token, { client: claims.iss, scopes: granted, exp: Date.now() + 300000 });
      return { status: 200, body: { access_token: token, token_type: 'bearer', expires_in: 300, scope: granted.join(' ') } };
    },
    authorize(bearer, needScope) {
      const t = issuedTokens.get(bearer);
      if (!t || t.exp < Date.now()) return { ok: false, status: 401 };
      if (!t.scopes.includes(needScope)) return { ok: false, status: 403 };
      return { ok: true };
    },
    // Proposed operation (MDR proposal): POST [base]/$receive-shl with Parameters {shlink, passcode?, appointment?}
    async receiveShl(bearer, params, appServer) {
      const auth = this.authorize(bearer, 'system/DocumentReference.c');
      if (!auth.ok) return { status: auth.status, body: outcome('error', auth.status === 401 ? 'login' : 'forbidden', 'token rejected') };
      const get = n => (params.parameter.find(p => p.name === n) || {});
      try {
        const bundle = await resolveShlink(get('shlink').valueString, get('passcode').valueString, name, appServer);
        const result = await file(bundle, { appointmentId: get('appointment').valueString });
        return { status: 200, body: outcome('information', 'informational', 'Pre-check-in received and filed: ' + result.filed.mustPersist.length + ' resources to reconciliation, ' + result.filed.intake.length + ' intake form(s), ' + result.filed.documents.length + ' document(s)'), result };
      } catch (e) { return { status: 422, body: outcome('error', 'processing', e.message) }; }
    },
    // Standards-only path: POST [base]/DocumentReference whose attachment.url is the shlink. Only works for links without a passcode.
    async createDocumentReference(bearer, docRef, appServer) {
      const auth = this.authorize(bearer, 'system/DocumentReference.c');
      if (!auth.ok) return { status: auth.status, body: outcome('error', 'login', 'token rejected') };
      try {
        const url = docRef.content[0].attachment.url;
        const p = parseShlink(url);
        if ((p.flag || '').includes('P')) throw new Error('DocumentReference has no field for a passcode; use the operation or a link without P');
        const apptId = (docRef.context && docRef.context.related && docRef.context.related[0] && docRef.context.related[0].reference || '').split('/')[1];
        const bundle = await resolveShlink(url, undefined, name, appServer);
        const result = await file(bundle, { appointmentId: apptId });
        return { status: 201, headers: { location: base + '/DocumentReference/' + uuid() }, body: outcome('information', 'informational', 'DocumentReference created; linked bundle fetched and filed'), result };
      } catch (e) { return { status: 422, body: outcome('error', 'processing', e.message) }; }
    },
    async scanQr(uri, appServer) {       // desk scan: KTC primary workflow
      try { const bundle = await resolveShlink(uri, undefined, name, appServer); const result = await file(bundle, {}); return { ok: true, result, bundle }; }
      catch (e) { return { ok: false, error: e.message }; }
    }
  };
}
function outcome(severity, code, text) { return { resourceType: 'OperationOutcome', issue: [{ severity, code, diagnostics: text }] }; }

// ---------- App side: SMART Backend Services client assertion, capability gate, route choice ----------
async function clientAssertion(clientKey, clientId, tokenEndpoint) {
  const now = Math.floor(Date.now() / 1000);
  return signJwt({ iss: clientId, sub: clientId, aud: tokenEndpoint, exp: now + 300, jti: uuid() }, clientKey, { typ: 'JWT' });
}
function capabilityGate(cap) {
  const rest = cap.rest[0];
  const tokenExt = (((rest.security || {}).extension || []).find(e => e.url === 'http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris') || { extension: [] }).extension;
  const token = (tokenExt.find(e => e.url === 'token') || {}).valueUri;
  const docRef = rest.resource.find(r => r.type === 'DocumentReference');
  const canCreateDocRef = Boolean(docRef && docRef.interaction.some(i => i.code === 'create'));
  const hasOp = (rest.operation || []).some(o => o.name === 'receive-shl');
  return { tokenEndpoint: token, canCreateDocRef, hasReceiveShl: hasOp, inboundSupported: Boolean(token) && (canCreateDocRef || hasOp) };
}
function chooseRoute({ connected, gate, pin }) {
  if (!connected) return { route: 'qr', reason: 'no EHR integration for this practice' };
  if (!gate.inboundSupported) return { route: 'qr', reason: 'EHR advertises no inbound path' };
  if (pin && !gate.hasReceiveShl) return { route: 'qr', reason: 'PIN set but EHR has no $receive-shl; DocumentReference cannot carry a passcode' };
  return { route: 'ehr', reason: gate.hasReceiveShl ? '$receive-shl advertised' : 'DocumentReference create advertised' };
}

// ---------- Device calendar (stand-in): visits the patient put in the phone calendar ----------
const DEVICE_CALENDAR = [
  { title: 'Dr. Okafor, annual physical', start: '2026-11-18T09:30:00-06:00', location: 'Prairie Ridge Family Medicine, 11200 Nall Ave, Leawood KS', notes: '' },
  { title: 'Dentist, cleaning', start: '2026-11-21T14:00:00-06:00', location: 'Mission Hills Dental, Overland Park KS', notes: '' },
  { title: 'Soccer, Kai', start: '2026-11-15T10:00:00-06:00', location: 'Swope Park', notes: '' }
];
function scanDeviceCalendar(events, lookaheadDays = 30) {
  const kw = /(dr\.?|doctor|dentist|dental|clinic|physical|exam|appointment|appt|ortho|eye|optom|ophthalm)/i;
  const now = Date.now(), horizon = now + lookaheadDays * 86400000;
  return events.filter(e => { const t = Date.parse(e.start); return t > now && t < horizon && (kw.test(e.title) || kw.test(e.location)); })
    .map(e => ({ ...e, guess: /dent/i.test(e.title + e.location) ? 'dental' : /ortho/i.test(e.title) ? 'ortho' : /eye|optom|ophthalm/i.test(e.title) ? 'eye' : 'primary', confidence: 'from calendar title; patient confirms' }));
}

root.PCI = { b64u, b64uDecode, b64uJson, randomBytes, uuid, nowIso, JWE_HEADER, JWE_HEADER_B64, encryptJwe, decryptJwe, generateSigningKey, signJwt, verifyJwt, buildShlink, parseShlink, textPdf,
  patient, PATIENT_ID, RECORDS, VISITS, recommend, QUESTIONNAIRES, buildQuestionnaire, buildQuestionnaireResponse, buildProvenance, IAL_EXT, buildPdfDocRef, ATTESTATION_EXT, buildAttestation, buildBundle, renderLines,
  createAppServer, createEhr, clientAssertion, capabilityGate, chooseRoute, DEVICE_CALENDAR, scanDeviceCalendar, sha256 };
})(typeof globalThis !== 'undefined' ? globalThis : this);
