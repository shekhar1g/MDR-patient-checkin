# App-initiated pre-check-in on SMART Health Links

A runnable demonstration of how a patient's app can start a visit check-in, package what the practice needs, and hand it over either as a QR code at the desk or by pushing it straight into the EHR before the visit. Built by MyDigiRecords for the CMS Health Technology Ecosystem Kill the Clipboard check-in discussion.

Live page: open `index.html` in any browser, or visit the GitHub Pages URL for this repo.

## What is real and what is simulated

Real, running in the browser:

- AES-256-GCM JWE as the SMART Health Links spec requires (`alg` dir, `enc` A256GCM, `cty` application/fhir+json). Verified to interoperate with the `jose` library in both directions.
- The KTC guide's App Attestation: an ES256 JWS with exactly `iss`, `iat`, `jti`, placed in `Bundle.meta.extension`, verified by the receiver against the app's JWKS.
- A SMART Backend Services client assertion (ES384) and a token endpoint that checks `iss`, `sub`, `aud`, `exp` and the signature.
- `shlink:/` payloads with a 256-bit path, a 43-character key, and the flag rules enforced (U cannot combine with P).
- A QR code that encodes the live link, and a PDF generated and carried in the bundle as a PatientSharedDocumentReference.

Simulated inside the page: the ID.me identity proofing step, the patient app's server, the EHR (its CapabilityStatement, token endpoint, MPI and chart), and the phone calendar read.

## Standards the page is built against

| Source | Version | Used for |
|---|---|---|
| Patient-Shared Health Documents via SMART Health Links (KTC guide) | v0.10.2, Draft for July 2026 | U flag, required expiry, recipient parameter, PatientSharedBundle and PatientSharedDocumentReference, PATAST, persistence tiers, App Attestation, expiry guidance |
| SMART Health Cards and Links IG, Health Links Specification | 1.0.0 STU 1 | Payload fields, flag definitions, manifest request and response, 401 with remainingAttempts, JWE parameters |
| US Core, QuestionnaireResponse profile | 9.0.0 | Intake form answers |
| SMART App Launch, Backend Services | current published | client_credentials grant, jwt-bearer client assertion, system scopes |
| Interoperable Digital Identity and Patient Matching | 2.0.0 | Statement that IAL levels are not in a code system in that guide |

## Two proposals in here that are not in any published guide

1. **`$receive-shl`**, a system-level operation an EHR can expose so an app can hand over a link with its passcode and the appointment it belongs to. Draft OperationDefinition in `fhir/OperationDefinition-receive-shl.json`. The alternative shown on the page, creating a DocumentReference whose `attachment.url` is the link, uses only existing FHIR but has no place for a passcode.
2. **An identity-assurance extension on Provenance** (`https://mydigirecords.com/fhir/StructureDefinition/identity-assurance`) carrying the IAL level, the credential service provider and the verification time. We would rather the group tell us where this belongs.

## Run the tests

```
npm install
npm test
```

`test/core.test.mjs` checks the protocol core against `jose` and the spec rules (27 checks). `test/page.test.mjs` drives the whole page through both paths in jsdom, connected EHR with a PIN and phone calendar without one (23 checks).

## Layout

- `index.html`: the built page. Self-contained apart from Google Fonts.
- `core.js`: the protocol core. Runs in the browser and in Node. Everything the page shows under "Show the code" is pulled from this file.
- `src-page.html`, `qrcode.bundle.js` and `build.py`: the page template, the QR encoder (node-qrcode, MIT, bundled with esbuild) and the one-step build that inlines both `core.js` and the encoder into the page. Edit these, then `npm run build`.
- `fhir/`: draft OperationDefinition.
- `test/`: the two test files.

## Hosting on GitHub Pages


Fictional patient and practices throughout. No data leaves the browser.
