namespace Cirreum.SignedRequest;

/// <summary>
/// Well-known RFC 9421 covered-component names. Derived components are prefixed with <c>@</c>;
/// field components are the (lowercased) HTTP field name.
/// </summary>
public static class SignatureComponentNames {

	/// <summary>The HTTP method (derived component <c>@method</c>), uppercased.</summary>
	public const string Method = "@method";

	/// <summary>The absolute request path (derived component <c>@path</c>).</summary>
	public const string Path = "@path";

	/// <summary>The query string including the leading <c>?</c> (derived component <c>@query</c>).</summary>
	public const string Query = "@query";

	/// <summary>The RFC 9530 Content-Digest field (covered as a field component).</summary>
	public const string ContentDigest = "content-digest";

}
