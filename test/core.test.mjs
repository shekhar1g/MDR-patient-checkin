import fs from 'node:fs';
import { compactDecrypt, CompactEncrypt, compactVerify, importJWK, SignJWT } from 'jose';
import assert from 'node:assert/strict';

eval(fs.readFileSync(new URL('../core.js', import.meta.url), 'utf8'));
const P = globalThis.PCI;
let n = 0; const ok = (name) => { n++; console.log('  ok', name); };

// 1. JWE interop: page encrypts, jose decrypts
const key = P.randomBytes(32);
const jwe = await P.encryptJwe({ resourceType: 'Bundle', type: 'collection' }, key);
const { plaintext, protectedHeader } = await compactDecrypt(jwe, key);
assert.deepEqual(JSON.parse(Buffer.from(plaintext).toString()), { resourceType: 'Bundle', type: 'collection' });
assert.deepEqual(protectedHeader, { alg: 'dir', enc: 'A256GCM', cty: 'application/fhir+json' }); ok('page JWE decrypts with jose, header exact');
// 2. jose encrypts, page decrypts
const j2 = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify({ a: 1 }))).setProtectedHeader({ alg: 'dir', enc: 'A256GCM', cty: 'application/fhir+json' }).encrypt(key);
assert.deepEqual((await P.decryptJwe(j2, key)).payload, { a: 1 }); ok('jose JWE decrypts in page code');
// 3. wrong key fails
await assert.rejects(P.decryptJwe(jwe, P.randomBytes(32))); ok('wrong key rejected');

// 4. SHL payload rules
const link = P.buildShlink({ url: 'https://app.example/shl/' + P.b64u(P.randomBytes(32)), keyBytes: key, exp: 1, flag: 'U', label: 'x' });
assert.equal(link.payload.key.length, 43); assert.ok(link.uri.startsWith('shlink:/')); assert.deepEqual(P.parseShlink('https://viewer.example#' + link.uri), link.payload); ok('shlink build/parse, 43-char key, viewer prefix accepted');
assert.throws(() => P.buildShlink({ url: 'https://a/b', keyBytes: key, flag: 'PU' }), /U SHALL NOT/); ok('U+P refused');
assert.throws(() => P.buildShlink({ url: 'https://a/' + 'x'.repeat(130), keyBytes: key, flag: 'U' }), /128/); ok('url >128 refused');

// 5. Attestation ES256: page signs, jose verifies; and page verifies its own
const appKey = await P.generateSigningKey('ES256');
const att = await P.buildAttestation(appKey, 'https://mydigirecords.com');
const pub = await importJWK(appKey.publicJwk, 'ES256');
const v = await compactVerify(att, pub);
const claims = JSON.parse(Buffer.from(v.payload).toString());
assert.deepEqual(Object.keys(claims).sort(), ['iat', 'iss', 'jti']); assert.equal(v.protectedHeader.alg, 'ES256'); assert.equal(v.protectedHeader.kid, appKey.publicJwk.kid); ok('attestation verifies in jose; exactly iss/iat/jti; ES256 + kid');
assert.ok((await P.verifyJwt(att, { keys: [appKey.publicJwk] })).ok); ok('page verifies attestation');
const tampered = att.slice(0, -4) + 'AAAA';
assert.equal((await P.verifyJwt(tampered, { keys: [appKey.publicJwk] })).ok, false); ok('tampered attestation fails');

// 6. Client assertion ES384 verified by jose; and jose-signed assertion accepted by simulated EHR token endpoint
const clientKey = await P.generateSigningKey('ES384');
const ca = await P.clientAssertion(clientKey, 'mdr-precheckin', 'https://ehr.example/fhir/oauth2/token');
const cv = await compactVerify(ca, await importJWK(clientKey.publicJwk, 'ES384'));
const cc = JSON.parse(Buffer.from(cv.payload).toString());
assert.equal(cc.iss, 'mdr-precheckin'); assert.equal(cc.sub, cc.iss); assert.equal(cc.aud, 'https://ehr.example/fhir/oauth2/token'); assert.ok(cc.exp - cc.iat <= 300 || cc.exp - Math.floor(Date.now()/1000) <= 300); assert.ok(cc.jti); ok('client assertion claims per SMART Backend Services');

const ehr = P.createEhr({ name: 'Prairie Ridge', base: 'https://ehr.example/fhir', clientRegistry: new Map([['mdr-precheckin', { jwks: { keys: [clientKey.publicJwk] }, scopes: ['system/DocumentReference.c'] }]]),
  trustedApps: new Map([['https://mydigirecords.com', { jwks: { keys: [appKey.publicJwk] } }]]),
  mpi: [{ mrn: 'E00412', family: 'Alvarez', given: 'Jordan', birthDate: '1979-03-14' }],
  appointments: [{ id: 'appt-1', encounterId: 'enc-77', start: '2026-11-18T09:30:00-06:00' }] });
const tok = await ehr.token({ grant_type: 'client_credentials', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: ca, scope: 'system/DocumentReference.c' });
assert.equal(tok.status, 200); assert.equal(tok.body.token_type, 'bearer'); ok('token issued for valid assertion');
const bad = await ehr.token({ grant_type: 'client_credentials', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: ca.slice(0, -3) + 'abc', scope: 'system/DocumentReference.c' });
assert.equal(bad.status, 401); ok('bad signature rejected at token endpoint');

// 7. Full flow: bundle -> host (U) -> desk scan; bundle -> host (P) -> $receive-shl with PIN; DocumentReference path refuses P
const idv = { ial: 'IAL2', csp: 'ID.me', verifiedAt: '2026-11-10T15:02:00Z' };
const { bundle, pdf } = await P.buildBundle({ selected: ['allergies', 'medications', 'conditions'], visitKey: 'primary', idv, appKey, appIss: 'https://mydigirecords.com' });
assert.equal(bundle.entry.filter(e => e.resource.resourceType === 'Patient').length, 1); assert.ok(!bundle.meta.profile); assert.equal(bundle.type, 'collection'); assert.ok(bundle.timestamp); ok('PatientSharedBundle shape');
assert.ok(Buffer.from(pdf).toString('latin1').startsWith('%PDF-1.4')); assert.ok(Buffer.from(pdf).toString('latin1').includes('%%EOF')); ok('PDF bytes well-formed header/trailer');
const doc = bundle.entry.map(e => e.resource).find(r => r.resourceType === 'DocumentReference');
assert.equal(doc.type.coding[0].code, '60591-5'); assert.equal(doc.meta.security[0].code, 'PATAST'); assert.equal(doc.category[0].coding[0].code, 'patient-shared'); ok('PatientSharedDocumentReference fields');
const qr = bundle.entry.map(e => e.resource).find(r => r.resourceType === 'QuestionnaireResponse');
assert.ok(qr.questionnaire.includes('|1.0')); assert.equal(qr.status, 'completed'); assert.ok(qr.author && qr.source); ok('US Core QuestionnaireResponse fields');

const app = P.createAppServer('https://mydigirecords.com');
const exp = Math.floor(Date.now() / 1000) + 900;
const u = await app.host(bundle, { flag: 'U', exp, label: 'Pre-visit, Prairie Ridge' });
const scan = await ehr.scanQr(u.link.uri, app);
assert.ok(scan.ok, scan.error); assert.equal(scan.result.attestation.ok, true); assert.equal(scan.result.match.matched, true); assert.equal(scan.result.ial.ial, 'IAL2'); assert.equal(scan.result.filed.mustPersist.length, 8); ok('desk scan: resolve, decrypt, attest, match, file');
assert.equal(app.audit[0].recipient, 'Prairie Ridge'); ok('audit log records recipient');

const p = await app.host(bundle, { flag: 'P', exp: exp + 3600, label: 'Pre-visit, Prairie Ridge', passcode: '4821' });
const params = { resourceType: 'Parameters', parameter: [{ name: 'shlink', valueString: p.link.uri }, { name: 'passcode', valueString: '4821' }, { name: 'appointment', valueString: 'appt-1' }] };
const r1 = await ehr.receiveShl(tok.body.access_token, params, app);
assert.equal(r1.status, 200, JSON.stringify(r1.body)); assert.equal(r1.result.appointment.encounterId, 'enc-77'); ok('$receive-shl with PIN binds to encounter');
const wrong = { ...params, parameter: params.parameter.map(x => x.name === 'passcode' ? { ...x, valueString: '0000' } : x) };
const r2 = await ehr.receiveShl(tok.body.access_token, wrong, app);
assert.equal(r2.status, 422); assert.match(r2.body.issue[0].diagnostics, /remainingAttempts=2/); ok('wrong PIN: 401 remainingAttempts surfaced');
const dr = { resourceType: 'DocumentReference', status: 'current', content: [{ attachment: { url: p.link.uri } }] };
const r3 = await ehr.createDocumentReference(tok.body.access_token, dr, app);
assert.equal(r3.status, 422); assert.match(r3.body.issue[0].diagnostics, /passcode/); ok('DocumentReference path refuses a P link');
const u2 = await app.host(bundle, { flag: 'U', exp: exp + 3600, label: 'x' });
const r4 = await ehr.createDocumentReference(tok.body.access_token, { ...dr, content: [{ attachment: { url: u2.link.uri } }], context: { related: [{ reference: 'Appointment/appt-1' }] } }, app);
assert.equal(r4.status, 201); ok('DocumentReference path works with a U link');
const r5 = await ehr.receiveShl('ehr_bogus', params, app);
assert.equal(r5.status, 401); ok('no token: 401');

// 8. Route choice + capability gate + calendar
const gate = P.capabilityGate(ehr.capability);
assert.ok(gate.inboundSupported && gate.hasReceiveShl && gate.canCreateDocRef); ok('capability gate reads token endpoint, DocRef create, operation');
assert.equal(P.chooseRoute({ connected: false, gate, pin: true }).route, 'qr');
assert.equal(P.chooseRoute({ connected: true, gate, pin: true }).route, 'ehr');
assert.equal(P.chooseRoute({ connected: true, gate: { ...gate, hasReceiveShl: false }, pin: true }).route, 'qr');
assert.equal(P.chooseRoute({ connected: true, gate: { ...gate, hasReceiveShl: false }, pin: false }).route, 'ehr'); ok('route choice');
const cal = P.scanDeviceCalendar(P.DEVICE_CALENDAR.map(e => ({ ...e, start: new Date(Date.now() + 3 * 86400000).toISOString() })));
assert.equal(cal.length, 2); assert.equal(cal.find(c => /Dentist/.test(c.title)).guess, 'dental'); ok('calendar scan finds visits, skips soccer');
for (const k of Object.keys(P.VISITS)) { const rec = P.recommend(k); assert.equal(rec.length, 6); assert.ok(rec.every(r => r.reason)); P.buildQuestionnaireResponse(k, {}); }
ok('all four visit types recommend + questionnaire');

console.log('\n' + n + ' checks passed');
