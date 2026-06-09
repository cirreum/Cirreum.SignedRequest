namespace Cirreum.SignedRequest;

/// <summary>
/// A single signature parsed from a request's <c>Signature</c> / <c>Signature-Input</c> headers
/// (RFC 9421). The <see cref="SignatureParamsValue"/> is preserved verbatim so the verifier
/// reconstructs the byte-identical signature base via <see cref="SignatureBaseBuilder.BuildBase"/>.
/// </summary>
public sealed record ParsedSignature {

	/// <summary>The signature label (the dictionary member key, e.g. <c>sig1</c>).</summary>
	public required string Label { get; init; }

	/// <summary>The ordered covered-component identifiers parsed from the inner list.</summary>
	public required IReadOnlyList<string> CoveredComponents { get; init; }

	/// <summary>The verbatim signature-params value (used as the <c>@signature-params</c> line).</summary>
	public required string SignatureParamsValue { get; init; }

	/// <summary>The <c>created</c> parameter (Unix seconds).</summary>
	public required long Created { get; init; }

	/// <summary>The optional <c>expires</c> parameter (Unix seconds).</summary>
	public long? Expires { get; init; }

	/// <summary>The <c>keyid</c> parameter.</summary>
	public required string KeyId { get; init; }

	/// <summary>The <c>alg</c> parameter.</summary>
	public required string Algorithm { get; init; }

	/// <summary>The optional <c>nonce</c> parameter.</summary>
	public string? Nonce { get; init; }

	/// <summary>The optional <c>tag</c> parameter.</summary>
	public string? Tag { get; init; }

	/// <summary>The decoded signature bytes from the <c>Signature</c> header.</summary>
	public required byte[] Signature { get; init; }

}
