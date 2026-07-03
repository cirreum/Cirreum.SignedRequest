# Cirreum.SignedRequest v1.0.0 — Migration Guide

> **From:** _(no prior version)_ &nbsp;•&nbsp; **To:** v1.0.0

## Why v1

This is the **initial release** of `Cirreum.SignedRequest`. There is no earlier
published version, so there is nothing for a consumer to migrate from.

The package holds the RFC 9421 (HTTP Message Signatures) and RFC 9530
(Content-Digest) primitives — the shared signature-base builder, the structured-field
wire parser, `Content-Digest` compute/verify, the pluggable signing-algorithm seam,
and the outbound signer. These were previously carried inline by the
`Cirreum.Authentication.SignedRequest` server scheme and the
`Cirreum.Authentication.SignedRequest.Client` SDK; they were consolidated into this
single dependency-free package so the two build against one source of truth and a
signed request verifies byte-identically on both sides (ADR-0021 §8). None of those
earlier arrangements were ever published to NuGet, so this consolidation is not a
consumer-visible migration.

---

## Breaking Changes — Find/Replace Table

None. Initial release.

---

## New Capabilities

See [`docs/RELEASE-NOTES-v1.0.0.md`](RELEASE-NOTES-v1.0.0.md) for the full surface
and usage examples.

---

## Migration Walkthrough

### 1. Add the package reference

```xml
<PackageReference Include="Cirreum.SignedRequest" Version="1.0.0" />
```

Most applications do not reference this package directly — they use the server scheme
(`Cirreum.Authentication.SignedRequest`) or the client SDK
(`Cirreum.Authentication.SignedRequest.Client`), both of which depend on it. Reference
it directly only to integrate RFC 9421 signing / verification into a custom surface.

---

## What Didn't Change

Everything — this is the first release.

---

## Downstream Package Impact

`Cirreum.Authentication.SignedRequest` (server scheme) and
`Cirreum.Authentication.SignedRequest.Client` (SDK) take a `PackageReference` on
`Cirreum.SignedRequest 1.0.0`. Both must reference this published version.
