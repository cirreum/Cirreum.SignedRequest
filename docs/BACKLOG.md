# Backlog

Deferred work for **Cirreum.SignedRequest**. Items here are tracked but not yet ready to ship — either
because the cost outweighs the benefit in isolation, or because they're waiting on a forcing function (a
related change, a consumer upgrade, a coordinated multi-repo rollout).

## How this file works

- Each item is a `###` heading so it can be linked to and parsed.
- Each item declares **`SemVer:`** (`Patch` | `Minor` | `Major` | `Unspecified`),
  **`Trigger:`** (the human-readable condition that will make it ready), and
  **`Noted:`** (the date the item was added).
- The Cirreum DevOps release scripts (`PatchRelease`, `MinorRelease`, `MajorRelease`) surface items
  at-or-below the requested bump level so the operator can decide whether to fold them in before tagging.
- Items that ship: move from this file to `docs/CHANGELOG.md` under `[Unreleased]`. Items that grow into
  design discussions: promote to an ADR.

## Queued

### Asymmetric signing algorithms (Ed25519 / X25519)

- **SemVer:** Minor
- **Trigger:** .NET 11 ships native Ed25519 / X25519 (Nov 2026), or a consumer needs an asymmetric M2M
  signature (the verifier holds only a public key) before then.
- **Noted:** 2026-06-08
- v1 ships `hmac-sha256` only — symmetric, so the verifier holds the shared secret at rest. The
  `ISignedRequestAlgorithm` / resolver seam is designed so an asymmetric algorithm registers additively, with
  no change to the signature base or wire format. Add the implementation when the preferred curve is native
  rather than taking an interim RSA-PSS or third-party-crypto dependency (ADR-0021 §4).

### Field-value canonicalization for non-`Content-Digest` covered fields

- **SemVer:** Minor
- **Trigger:** A covered set beyond the default (`@method` / `@path` / `@query` / `content-digest`) is needed
  — e.g. signing a custom or standard HTTP field — across signer and verifier.
- **Noted:** 2026-06-08
- The builder consumes already-finalized field values from `SignatureBaseComponents.Fields`; today only
  `Content-Digest` is exercised. Before a second covered field is supported, add RFC 9421 §2.1 field-value
  canonicalization (OWS strip, multi-line comma-join, obs-fold collapse) inside `FromRequest` so signer and
  verifier produce the byte-identical field value, with a cross-surface conformance test over awkward inputs.
