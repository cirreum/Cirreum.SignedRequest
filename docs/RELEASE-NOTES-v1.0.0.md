# Cirreum.SignedRequest 1.0.0 — the shared RFC 9421 / RFC 9530 core

The dependency-free primitives for HTTP Message Signatures (RFC 9421) and
Content-Digest (RFC 9530): the shared signature base, the wire parser, the digest
compute/verify, the pluggable algorithm seam, and the outbound signer. This is the
common language spoken by the `Cirreum.Authentication.SignedRequest` server scheme
and the `Cirreum.Authentication.SignedRequest.Client` SDK, so a request signed on one
side verifies byte-for-byte on the other.

Strictly additive — initial release. No dependencies beyond the BCL.

---

## Why this release exists

RFC 9421 only interoperates when the signer and the verifier reconstruct the **exact
same** signature base. When those two live in different packages — one signing
outbound webhooks / API calls, one verifying inbound requests — the canonicalization
rules (method casing, percent-encoding, `@path` / `@query` normalization, the
`@signature-params` line) have to agree to the byte. The way to guarantee that is to
give both sides one implementation rather than two that are "kept in sync."

`Cirreum.SignedRequest` is that one implementation. It is pure BCL — no Cirreum,
ASP.NET, or third-party dependencies — so both the server scheme and the standalone
client SDK reference it and can never drift.

---

## What's new

### `SignatureBaseBuilder`

```csharp
var signing = SignatureBaseBuilder.BuildForSigning(components, parameters);
// signer: HMAC over signing.SignatureBase; emit Signature / Signature-Input
var baseBytes = SignatureBaseBuilder.BuildBase(components, entry.CoveredComponents, entry.SignatureParamsValue);
// verifier: rebuild the byte-identical base from the received params, then verify
```

Builds the RFC 9421 signature base (the ordered, labelled `"component": value` lines
terminated by `"@signature-params"`). The verifier replays the received params
verbatim, so its reconstructed base is byte-identical to what was signed.

### `SignatureBaseComponents.FromRequest(method, path, query, fields)`

The single value normalizer — method casing, `@path` / `@query` to their RFC 9421
§2.2.6/§2.2.7 + RFC 3986 §6.2.2 canonical form, empty-path default, case-insensitive
field keys. Both sides project their host request onto it, so canonicalization lives
in exactly one place. `@path` is bound in dot-segment-normalized form; authorization
keys on the normalized path.

### `SignatureWireParser` / `ParsedSignature`

Defensive RFC 8941 parsing of the `Signature` / `Signature-Input` structured-field
headers. Every malformation returns `false` rather than throwing; duplicate dictionary
labels / parameters are rejected.

### `ContentDigest`

RFC 9530 `Content-Digest` compute and constant-time verify (SHA-256), binding the
request body into the signature regardless of method.

### `ISignedRequestAlgorithm` / `ISignedRequestAlgorithmResolver`

The pluggable signing / verification seam, with `HmacSha256SignedRequestAlgorithm`
(`hmac-sha256`) built in. Additional algorithms (e.g. Ed25519) register additively
without touching the signature base or wire format.

### The outbound signer

```csharp
// Sign a prepared request:
await request.SignRequestAsync(keyId, signingSecret);

// Or sign + send with a JSON body in one call:
var response = await client.SendSignedAsync(
    HttpMethod.Post, "/v1/events", keyId, signingSecret, new { eventType = "order.placed", id });
```

`HttpRequestMessage.SignRequestAsync(...)` / `HttpClient.SendSignedAsync(...)` (in
`System.Net.Http`, so they surface ambiently), with `OutboundSigningOptions` and
`SigningCredentials`. This is the single signer the server scheme (outbound webhooks)
and the client SDK (outbound API calls) both use — built on `SignatureBaseBuilder`, so
the signer cannot drift from the verifier.

### `SignedRequestHeaders`

The RFC 9421 / RFC 9530 header names (`Signature`, `Signature-Input`, `Content-Digest`)
in one place, referenced by the signer and the server verifier so they never diverge.

---

## Compatibility

- **Strictly additive.** Initial release.
- **No dependencies** beyond the BCL — no Cirreum, ASP.NET, or third-party packages.
- **Conformance** is verified against RFC 4231 (HMAC-SHA-256) and RFC 9530
  (Content-Digest) published test vectors; the signature base is locked by a
  known-answer vector; the wire parser is fuzz-hardened against the RFC 9421 §7
  never-throw contract.

---

## Coordinated downstream work

This release unblocks the first releases of `Cirreum.Authentication.SignedRequest.Client`
(SDK — depends only on this package) and `Cirreum.Authentication.SignedRequest` (server
scheme — depends on this package plus the auth foundation).

---

## See also

- `Cirreum.Authentication.SignedRequest` — the server scheme (verify inbound, sign outbound webhooks)
- `Cirreum.Authentication.SignedRequest.Client` — the consumer SDK (sign outbound calls, validate inbound webhooks)
