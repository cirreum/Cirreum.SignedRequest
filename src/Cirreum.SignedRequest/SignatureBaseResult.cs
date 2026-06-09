namespace Cirreum.SignedRequest;

/// <summary>
/// The result of building a signing-side signature base: the bytes to sign and the serialized
/// <c>@signature-params</c> value (which becomes the <c>Signature-Input</c> header value).
/// </summary>
/// <param name="SignatureBase">The RFC 9421 signature base bytes to sign.</param>
/// <param name="SignatureParamsValue">The serialized signature-params value (RFC 8941 inner list +
/// parameters) — the <c>Signature-Input</c> header value for the signature label.</param>
public sealed record SignatureBaseResult(byte[] SignatureBase, string SignatureParamsValue);
