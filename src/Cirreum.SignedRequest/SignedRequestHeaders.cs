namespace Cirreum.SignedRequest;

/// <summary>
/// The RFC 9421 / RFC 9530 HTTP header names a signed request carries. Defined once here so the outbound
/// signer, the server verifier, and the client SDK all reference a single source of truth rather than
/// re-declaring the literals per package.
/// </summary>
public static class SignedRequestHeaders {

	/// <summary>The RFC 9421 <c>Signature</c> header name.</summary>
	public const string Signature = "Signature";

	/// <summary>The RFC 9421 <c>Signature-Input</c> header name.</summary>
	public const string SignatureInput = "Signature-Input";

	/// <summary>The RFC 9530 <c>Content-Digest</c> header name.</summary>
	public const string ContentDigest = "Content-Digest";
}
