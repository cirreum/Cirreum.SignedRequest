# Changelog

All notable changes to **Cirreum.SignedRequest** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Initial release of **Cirreum.SignedRequest** — the shared, dependency-free RFC 9421 (HTTP Message
  Signatures) and RFC 9530 (Content-Digest) primitives consumed identically by the
  `Cirreum.Authentication.SignedRequest` server scheme and the `Cirreum.Authentication.SignedRequest.Client`
  SDK, so a signed request verifies byte-identically on both sides and the two can never drift (ADR-0021 §8).
  Pure BCL — no Cirreum, ASP.NET, or third-party dependencies.
- `SignatureBaseBuilder` — builds the RFC 9421 signature base (the ordered, labelled `"component": value`
  lines terminated by `"@signature-params"`) and serializes the signature-params value. The verify side
  replays the received params verbatim, so the reconstructed base is byte-identical to what was signed.
- `SignatureBaseComponents` with `FromRequest(method, path, query, fields)` — the single value normalizer
  (uppercases the method, normalizes `@query` to its RFC 9421 form, defaults an empty path to `/`, keys
  fields case-insensitively) that the per-side adapters project onto, so canonicalization lives in exactly
  one place rather than drifting across signer and verifier.
- `SignatureWireParser` / `ParsedSignature` — defensive RFC 8941 parsing of the `Signature` /
  `Signature-Input` structured-field headers. Every malformation returns `false` rather than throwing, and
  duplicate dictionary labels / parameters are rejected.
- `ContentDigest` — RFC 9530 `Content-Digest` compute and constant-time verify (SHA-256), binding the
  request body into the signature regardless of method. `Verify` accepts the canonical byte-sequence form
  and tolerates RFC 8941 member parameters; it is a SignedRequest helper, not a general structured-field
  parser.
- `ISignedRequestAlgorithm` / `ISignedRequestAlgorithmResolver` — the pluggable signing / verification seam,
  with `HmacSha256SignedRequestAlgorithm` (`hmac-sha256`) built in; additional algorithms register additively.
- The outbound signer — `HttpRequestMessage.SignRequestAsync(...)` / `HttpClient.SendSignedAsync(...)` extensions
  (`System.Net.Http`), `OutboundSigningOptions`, and `SigningCredentials` — the single implementation shared by
  the `Cirreum.Authentication.SignedRequest` server scheme (outbound webhooks) and the `.Client` SDK (outbound
  API calls), so a signed request built anywhere verifies byte-identically. Built on the shared signature-base
  builder — the signer cannot drift from the verifier.
- `SignedRequestHeaders` — the RFC 9421 / RFC 9530 header names (`Signature`, `Signature-Input`, `Content-Digest`)
  in one place, referenced by the signer and the server verifier so they never diverge.
