namespace Cirreum.SignedRequest;

/// <summary>
/// The RFC 9421 signature parameters — the covered-component list plus the metadata serialized into
/// the <c>@signature-params</c> line and the <c>Signature-Input</c> header value.
/// </summary>
public sealed class SignatureParameters {

	/// <summary>
	/// The ordered covered-component identifiers (e.g. <c>@method</c>, <c>@path</c>, <c>@query</c>,
	/// <c>content-digest</c>). Order is significant and preserved in the signature base.
	/// </summary>
	public required IReadOnlyList<string> CoveredComponents { get; init; }

	/// <summary>The key identifier (<c>keyid</c>) selecting the verification key.</summary>
	public required string KeyId { get; init; }

	/// <summary>The algorithm identifier (<c>alg</c>), e.g. <c>hmac-sha256</c>.</summary>
	public required string Algorithm { get; init; }

	/// <summary>The signature creation time (<c>created</c>) as Unix seconds.</summary>
	public required long Created { get; init; }

	/// <summary>The optional signature expiry (<c>expires</c>) as Unix seconds.</summary>
	public long? Expires { get; init; }

	/// <summary>The optional single-use nonce (<c>nonce</c>) for replay protection.</summary>
	public string? Nonce { get; init; }

	/// <summary>The optional application tag (<c>tag</c>).</summary>
	public string? Tag { get; init; }

}
