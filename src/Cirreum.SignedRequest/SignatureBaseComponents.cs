namespace Cirreum.SignedRequest;

/// <summary>
/// The neutral request components a signature base is built from (ADR-0021 §8). This type carries no
/// ASP.NET (<c>HttpRequest</c>) or <c>HttpClient</c> (<c>HttpRequestMessage</c>) dependency — the
/// per-side adapters in the server and client packages project their host request type onto it, so
/// signer and verifier construct the byte-identical signature base from the same builder.
/// </summary>
public sealed class SignatureBaseComponents {

	/// <summary>The HTTP method, uppercased (the <c>@method</c> value).</summary>
	public required string Method { get; init; }

	/// <summary>The absolute request path (the <c>@path</c> value), e.g. <c>/api/orders</c>.</summary>
	public required string Path { get; init; }

	/// <summary>
	/// The query string for the <c>@query</c> value, including the leading <c>?</c>. Per RFC 9421 this
	/// is <c>?</c> when there is no query.
	/// </summary>
	public string Query { get; init; } = "?";

	/// <summary>
	/// The covered HTTP field values, keyed case-insensitively by field name (e.g. <c>content-digest</c>).
	/// Used for any non-derived covered component.
	/// </summary>
	public IReadOnlyDictionary<string, string> Fields { get; init; } =
		new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Builds the neutral components from raw request primitives, applying ALL value canonicalization in
	/// this one place (ADR-0021 §8) so the server and client adapters perform mechanical extraction only and
	/// cannot drift. Adapters pass whatever their host produced for the path — server
	/// <c>HttpRequest.Path.ToUriComponent()</c> (re-encoded), client <c>Uri.AbsolutePath</c> (unreserved
	/// decoded), or a raw relative target — and the raw query; this uppercases the method, normalizes
	/// <c>@path</c> and <c>@query</c> to their RFC 9421 §2.2.6/§2.2.7 + RFC 3986 §6.2.2 canonical form
	/// (uppercase percent-hex, decoded unreserved octets, resolved dot-segments) so a path/query extracted
	/// differently on each side still yields the byte-identical signature base, defaults an empty path to
	/// <c>/</c> and an absent query to a bare <c>?</c>, and stores fields keyed case-insensitively.
	/// </summary>
	public static SignatureBaseComponents FromRequest(
		string method,
		string path,
		string? query,
		IEnumerable<KeyValuePair<string, string>>? fields = null) {

		ArgumentException.ThrowIfNullOrWhiteSpace(method);

		return new SignatureBaseComponents {
			Method = method.ToUpperInvariant(),
			Path = NormalizePath(path),
			Query = NormalizeQuery(query),
			Fields = NormalizeFields(fields),
		};
	}

	// RFC 9421 §2.2.6 + RFC 3986 §6.2.2: @path is the absolute path in normalized percent-encoded form.
	// Adapters may hand us a decoded (Uri.AbsolutePath), re-encoded (ToUriComponent()), or raw-relative path;
	// re-parsing through the BCL's RFC 3986 path canonicalizer collapses all of those to one byte sequence.
	private static string NormalizePath(string? path) {
		if (string.IsNullOrEmpty(path)) {
			return "/";
		}

		var withLeadingSlash = path[0] == '/' ? path : "/" + path;
		if (Uri.TryCreate("http://_" + withLeadingSlash, UriKind.Absolute, out var uri)) {
			var normalized = uri.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
			return CanonicalizeHex(normalized.Length == 0 ? "/" : "/" + normalized);
		}

		return CanonicalizeHex(withLeadingSlash);
	}

	// RFC 9421 §2.2.7: @query is the query including the leading '?'; no query yields the single char "?".
	// Canonicalized through the same RFC 3986 normalizer so signer and verifier converge on encoding and case.
	private static string NormalizeQuery(string? query) {
		var trimmed = string.IsNullOrEmpty(query) ? string.Empty : (query[0] == '?' ? query[1..] : query);
		if (trimmed.Length == 0) {
			return "?";
		}

		if (Uri.TryCreate("http://_/?" + trimmed, UriKind.Absolute, out var uri)) {
			return CanonicalizeHex("?" + uri.GetComponents(UriComponents.Query, UriFormat.UriEscaped));
		}

		return CanonicalizeHex("?" + trimmed);
	}

	// RFC 3986 §6.2.2.1: percent-encoding hex digits are case-insensitive but canonically uppercase. System.Uri
	// preserves the original case of percent-encodings it does not decode (e.g. %2f stays %2f), so uppercase
	// them explicitly — this is the step that makes a lower-case wire encoding on one side and an upper-case
	// (or re-encoded) form on the other converge to the byte-identical signature base.
	private static string CanonicalizeHex(string value) {
		var index = value.IndexOf('%');
		if (index < 0) {
			return value;
		}

		var chars = value.ToCharArray();
		for (var i = index; i <= chars.Length - 3; i++) {
			if (chars[i] == '%' && Uri.IsHexDigit(chars[i + 1]) && Uri.IsHexDigit(chars[i + 2])) {
				chars[i + 1] = char.ToUpperInvariant(chars[i + 1]);
				chars[i + 2] = char.ToUpperInvariant(chars[i + 2]);
			}
		}

		return new string(chars);
	}

	private static Dictionary<string, string> NormalizeFields(IEnumerable<KeyValuePair<string, string>>? fields) {
		var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		if (fields is not null) {
			foreach (var (name, value) in fields) {
				map[name] = value;
			}
		}

		return map;
	}

}