import fs from 'node:fs';
import { JSDOM } from 'jsdom';
import assert from 'node:assert/strict';

const html = fs.readFileSync(new URL('../index.html', import.meta.url), 'utf8')
  .replace(/<script src="https:\/\/cdn\.jsdelivr[^"]*"><\/script>/, '')   // CDN not reachable in jsdom
  .replace(/<link[^>]*fonts[^>]*>/g, '');
const errors = [];
const dom = new JSDOM(html, { runScripts: 'dangerously', pretendToBeVisual: true, beforeParse(w) {
  Object.defineProperty(w, "crypto", { value: globalThis.crypto }); w.TextEncoder = TextEncoder; w.TextDecoder = TextDecoder;
  w.HTMLElement.prototype.scrollIntoView = () => {};
  w.HTMLCanvasElement.prototype.getContext = () => ({});
  w.URL.createObjectURL = () => 'blob:x'; w.alert = m => errors.push('alert: ' + m);
  w.__realQR = true;
  w.addEventListener('error', e => errors.push(String(e.error || e.message)));
} });
const w = dom.window, d = w.document; const $ = s => d.querySelector(s);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const click = s => { const el = $(s); assert.ok(el, 'missing ' + s); assert.ok(!el.disabled, s + ' disabled'); el.click(); };
let n = 0; const ok = m => { n++; console.log('  ok', m); };
await sleep(400);
assert.ok(w.PCI, 'core loaded'); ok('core inlined and loaded');
assert.ok(!$('pre[data-code]').textContent.includes('not found')); d.querySelectorAll('pre[data-code]').forEach(p => assert.ok(!p.textContent.includes('not found'), 'code missing: ' + p.dataset.code)); ok('every show-the-code panel resolved its functions');

// 1
click('#btn-idv'); await sleep(50);
assert.match($('#art-idv').textContent, /IAL2/); assert.ok(!$('#s2').classList.contains('locked')); ok('step 1 identity record, step 2 unlocked');
// 2 connected
click('#btn-fetch-appt'); await sleep(50); assert.match($('#art-visit').textContent, /"resourceType": "Appointment"/); click('#btn-use-appt'); await sleep(50);
assert.match($('#visit-summary').textContent, /appt-1/); assert.ok(!$('#s3').classList.contains('locked')); ok('step 2 appointment read and chosen');
// 3
assert.match($('#art-qr').textContent, /precheckin-primary-care\|1\.0/);
const inp = $('#q-reason'); inp.value = 'Changed answer here'; $('#intake-form').dispatchEvent(new w.Event('input', { bubbles: true })); await sleep(20);
assert.match($('#art-qr').textContent, /Changed answer here/); ok('step 3 live QuestionnaireResponse tracks edits');
click('#btn-intake-done'); await sleep(50);
// 4
const boxes = [...d.querySelectorAll('#rec-table input')]; assert.equal(boxes.length, 6); assert.ok(boxes.every(b => b.checked)); ok('step 4 primary care suggests all six');
boxes.find(b => b.dataset.k === 'insurance').checked = false; $('#rec-table').dispatchEvent(new w.Event('change', { bubbles: true }));
click('#btn-rec-done'); await sleep(50);
// 5
assert.match($('#art-policy').textContent, /"flag": "P"/); assert.match($('#art-policy').textContent, /"flag": "U"/); ok('step 5 policy: QR U, push P');
click('#btn-policy-done'); await sleep(50);
// 6
click('#btn-build'); await sleep(600);
assert.match($('#build-status').textContent, /two links hosted/); const bt = $('#art-bundle').textContent;
assert.ok(!/Coverage/.test(bt), 'deselected insurance must be absent'); assert.match(bt, /app-attestation/); assert.match(bt, /PATAST/); assert.match(bt, /QuestionnaireResponse/); assert.match(bt, /Provenance/); ok('step 6 bundle built; deselected set absent; attestation, PDF docref, QR, provenance present');
assert.match($('#art-att').textContent, /"alg": "ES256"/); assert.match($('#art-shl').textContent, /"flag": "P"/); ok('attestation ES256; push link P');
// 7
const liveUri = d.querySelector('#art-shl').textContent; assert.match(liveUri, /"flag": "U"/); const svg = await w.QRCode.toString('shlink:/' + 'A'.repeat(320), { type: 'svg', errorCorrectionLevel: 'L' }); assert.ok(svg.includes('<svg') && svg.length > 2000); ok('inline QR encoder renders a 320-char shlink');
assert.match($('#qr-count').textContent, /^1[45]:\d\d$/); ok('countdown running from 15 min');
click('#btn-scan'); await sleep(300);
assert.match($('#art-scan').textContent, /recognized app: https:\/\/mydigirecords.com/); assert.match($('#art-scan').textContent, /"matched": true/); assert.match($('#art-scan').textContent, /IAL2 via ID.me/); ok('desk scan: GET+decrypt+attest+match');
assert.match($('#art-audit').textContent, /GET \(U flag\)/); ok('audit shows recipient fetch');
// 8
click('#btn-gate'); await sleep(300);
assert.match($('#art-gate').textContent, /"hasReceiveShl": true/); assert.match($('#art-gate').textContent, /"route": "ehr"/); assert.match($('#art-token').textContent, /"access_token"/); assert.match($('#art-token').textContent, /"status": 200/); ok('8.1 gate + token');
click('#btn-dispatch'); await sleep(400);
assert.match($('#art-req').textContent, /\$receive-shl/); assert.match($('#art-res').textContent, /"status": 200/); assert.match($('#art-manifest').textContent, /POST manifest|POST https/); assert.match($('#art-verify').textContent, /enc-77/); assert.match($('#art-chart').textContent, /pending clinician/); ok('8.2–8.5 operation path with PIN: manifest, encounter enc-77, chart filed');
assert.ok($('#status-tl').children[4].classList.contains('on')); ok('8.6 status reaches Retrieved by practice');
// DocumentReference path with a P link must be refused
d.querySelector('input[name=dm][value=docref]').checked = true; click('#btn-dispatch'); await sleep(300);
assert.match($('#art-res').textContent, /422/); assert.match($('#art-res').textContent, /passcode/); ok('DocumentReference path refuses a PIN link with 422');

// ----- second run: calendar path, no PIN, DocumentReference path -----
const dom2 = new JSDOM(html.replace(/<script src="https:\/\/cdn[^>]*><\/script>/, ''), { runScripts: 'dangerously', pretendToBeVisual: true, beforeParse(w2) {
  Object.defineProperty(w2, "crypto", { value: globalThis.crypto }); w2.TextEncoder = TextEncoder; w2.TextDecoder = TextDecoder; w2.HTMLElement.prototype.scrollIntoView = () => {}; w2.HTMLCanvasElement.prototype.getContext = () => ({});  w2.alert = m => errors.push('alert2: ' + m); w2.addEventListener('error', e => errors.push(String(e.error || e.message))); } });
const d2 = dom2.window.document, $2 = s => d2.querySelector(s), c2 = s => $2(s).click();
await sleep(400);
c2('#btn-idv'); await sleep(30);
d2.querySelector('#visit-mode input[value=calendar]').checked = true; d2.querySelector('#visit-mode input[value=calendar]').dispatchEvent(new dom2.window.Event('change'));
c2('#btn-scan-cal'); await sleep(30); const cals = d2.querySelectorAll('input[name=cal]'); assert.equal(cals.length, 2); cals[1].checked = true; c2('#btn-use-cal'); await sleep(30);
assert.match($2('#visit-summary').textContent, /Dental/); assert.match($2('#visit-summary').textContent, /none \(QR route/); ok('calendar path: dentist found, dental form chosen, no EHR id');
c2('#btn-intake-done'); await sleep(30);
const dentalBoxes = [...d2.querySelectorAll('#rec-table input')]; assert.equal(dentalBoxes.find(b => b.dataset.k === 'immunizations').checked, false); assert.equal(dentalBoxes.find(b => b.dataset.k === 'vitals').checked, true); ok('dental: immunizations off, vitals on');
c2('#btn-rec-done'); await sleep(30);
$2('#pin-on').checked = false; $2('#pin-on').dispatchEvent(new dom2.window.Event('input', { bubbles: true })); c2('#btn-policy-done'); await sleep(30);
assert.ok(!/"flag": "P"/.test($2('#art-policy').textContent)); ok('PIN off: both links U');
c2('#btn-build'); await sleep(600); c2('#btn-scan'); await sleep(300); assert.match($2('#art-scan').textContent, /"matched": true/); ok('calendar path desk scan files');
c2('#btn-gate'); await sleep(300); assert.match($2('#art-gate').textContent, /"route": "qr"/); ok('not connected: route decision is qr');
d2.querySelector('input[name=dm][value=docref]').checked = true; c2('#btn-dispatch'); await sleep(400);
assert.match($2('#art-res').textContent, /"status": 201/); assert.match($2('#art-verify').textContent, /walk-in queue/); ok('DocumentReference path with U link: 201, unbound encounter');

console.log('\nJS errors:', errors.length ? errors : 'none');
console.log(n + ' page checks passed');
process.exit(errors.length ? 1 : 0);
