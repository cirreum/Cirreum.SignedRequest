# Cirreum.SignedRequest

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.SignedRequest.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.SignedRequest/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.SignedRequest.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.SignedRequest/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.SignedRequest?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.SignedRequest/releases)
[![License](https://img.shields.io/badge/license-MIT-F2F2F2?style=flat-square&labelColor=1F1F1F)](https://github.com/cirreum/Cirreum.SignedRequest/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**HTTP Message Signatures and Content-Digest primitives for .NET, with a shared signature base that keeps Cirreum signers and verifiers aligned.**

## Overview

**Cirreum.SignedRequest** is the pure, dependency-free core of the SignedRequest scheme: the RFC 9421 / RFC 9530 building blocks that the server-side scheme (`Cirreum.Authentication.SignedRequest`) and the client SDK (`Cirreum.Authentication.SignedRequest.Client`) consume **identically**, so a signed request verifies byte-for-byte on both sides.

- **`SignatureBaseBuilder`** — builds the RFC 9421 signature base (the ordered, labelled `"component": value` lines terminated by `"@signature-params"`) and serializes the signature-params value. The verifier replays the received params verbatim, so its reconstructed base is byte-identical to what was signed.
- **`SignatureBaseComponents.FromRequest(...)`** — the single value normalizer (method casing, `@query` form, empty-path default, case-insensitive field keys). Per-side adapters project onto it, so canonicalization happens in exactly one place rather than drifting across signer and verifier.
- **`SignatureWireParser` / `ParsedSignature`** — defensive RFC 8941 parsing of the `Signature` / `Signature-Input` headers; every malformation returns `false` rather than throwing.
- **`ContentDigest`** — RFC 9530 `Content-Digest` compute and constant-time verify (SHA-256), binding the request body into the signature regardless of method.
- **`ISignedRequestAlgorithm` / `ISignedRequestAlgorithmResolver`** — the pluggable signing / verification seam, with `HmacSha256SignedRequestAlgorithm` (`hmac-sha256`) built in; new algorithms register additively.
- **`HttpRequestMessage.SignRequestAsync(...)` / `HttpClient.SendSignedAsync(...)`** — the ready-made outbound signer (with `OutboundSigningOptions` and `SigningCredentials`, in `System.Net.Http`). This is the single signer the server scheme and the client SDK both surface, so a request signed on either side verifies byte-identically on the other.

It has **no dependencies** beyond the BCL — no Cirreum, ASP.NET, or third-party packages.

## Installation

```bash
dotnet add package Cirreum.SignedRequest
```

## Usage

Most applications don't use this package directly — they use the server scheme (`Cirreum.Authentication.SignedRequest`) or the client SDK (`Cirreum.Authentication.SignedRequest.Client`), both of which build on these primitives. Reach for it directly only to integrate RFC 9421 signing / verification into a custom surface.

The signer and verifier build the **same** base from the same components:

```csharp
using Cirreum.SignedRequest;

// One place canonicalizes request primitives — both sides call it identically:
var components = SignatureBaseComponents.FromRequest(
    method: "POST",
    path: "/api/orders",
    query: "?page=1",
    fields: [new("content-digest", ContentDigest.Compute(body))]);

var parameters = new SignatureParameters {
    CoveredComponents = ["@method", "@path", "@query", "content-digest"],
    KeyId = "svc-a",
    Algorithm = "hmac-sha256",
    Created = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    Nonce = nonce,   // client-generated, >= 128-bit
};

// Signer — build the base, sign it, emit Signature / Signature-Input:
var signing = SignatureBaseBuilder.BuildForSigning(components, parameters);
var signature = new HmacSha256SignedRequestAlgorithm().Sign(signing.SignatureBase, keyBytes);

// Verifier — parse the headers, rebuild the byte-identical base, verify:
SignatureWireParser.TryParse(signatureInput, signatureHeader, out var entries);
var entry = entries[0];
var baseBytes = SignatureBaseBuilder.BuildBase(components, entry.CoveredComponents, entry.SignatureParamsValue);
var ok = new HmacSha256SignedRequestAlgorithm().Verify(baseBytes, entry.Signature, keyBytes)
    && ContentDigest.Verify(contentDigestHeader, body);
```

## RFC conformance profile

> Cirreum SignedRequest implements a constrained Cirreum profile of RFC 9421 and RFC 9530. The implementation intentionally supports the covered components, algorithms, digest forms, and validation behavior documented here; unsupported general RFC features are out of scope unless explicitly listed.

| Area | Supported | Not supported |
|---|---|---|
| Covered components | `@method`, `@path`, `@query`, HTTP fields (`content-digest`) | `@authority` (intentionally dropped), `@target-uri`, `@scheme`, `@status` (response signing), `@query-param`, component parameters (`sf` / `key` / `bs` / `req`) |
| Algorithms | `hmac-sha256` | others are additive via `ISignedRequestAlgorithm` (e.g. Ed25519) |
| Digest (RFC 9530) | `Content-Digest` with `sha-256` | other digest algorithms (ignored), `Repr-Digest` / `Want-*-Digest` |
| Signatures per request | exactly one | multi-signature messages are rejected |
| Structured fields (RFC 8941) | the dictionary / inner-list / string / byte-sequence / integer subset these headers use | a general RFC 8941 parser |

`SignatureBaseComponents.FromRequest` normalizes `@path` / `@query` to the RFC 9421 §2.2.6/§2.2.7 + RFC 3986 §6.2.2 canonical form in this one shared place, so a signer and verifier on different hosts converge on the byte-identical base. Conformance is verified against RFC 4231 (HMAC-SHA-256) and RFC 9530 (Content-Digest) published test vectors, the signature base is locked by a known-answer vector, and the wire parser is fuzz-hardened against the RFC 9421 §7 never-throw contract.

## Contribution Guidelines

1. **Be conservative with new abstractions**  
   The API surface must remain stable and meaningful.

2. **Limit dependency expansion**  
   This package is intentionally BCL-only; keep it that way.

3. **Favor additive, non-breaking changes**  
   Breaking changes ripple through the entire ecosystem.

4. **Include thorough unit tests**  
   All primitives should be independently testable, with cross-surface conformance over awkward inputs.

5. **Document architectural decisions**  
   Context and reasoning should be clear for future maintainers.

6. **Follow .NET conventions**  
   Use established patterns from the BCL and Microsoft.Extensions.* libraries.

## Versioning

Cirreum.SignedRequest follows [Semantic Versioning](https://semver.org/):

- **Major** - Breaking API changes
- **Minor** - New features, backward compatible
- **Patch** - Bug fixes, backward compatible

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Cirreum Foundation Framework**  
*Layered simplicity for modern .NET*
