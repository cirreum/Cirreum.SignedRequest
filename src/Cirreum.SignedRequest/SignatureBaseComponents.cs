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
	/// <remarks>
	/// <c>@path</c> is bound in RFC 3986 §5.2.4 normalized form, so dot-segments are resolved and two spellings
	/// of the same resource (<c>/x/../admin</c> and <c>/admin</c>) collapse to one signature base. This
	/// collision is deliberate: the signature covers exactly the path the ASP.NET pipeline routes and
	/// authorizes on (which is itself dot-segment-normalized), so a signed request is bound to a single
	/// canonical resource, not to a particular spelling of it. Authorization MUST therefore key on the
	/// normalized <c>HttpRequest.Path</c>, never on a raw upstream request-target.
	/// </remarks>
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
		var guarded = EscapeComponentDelimiters(withLeadingSlash, isPath: true);
		if (Uri.TryCreate("http://_" + guarded, UriKind.Absolute, out var uri)) {
			var normalized = uri.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
			return CanonicalizeHex(normalized.Length == 0 ? "/" : "/" + normalized);
		}

		return CanonicalizeHex(guarded);
	}

	// RFC 9421 §2.2.7: @query is the query including the leading '?'; no query yields the single char "?".
	// Canonicalized through the same RFC 3986 normalizer so signer and verifier converge on encoding and case.
	private static string NormalizeQuery(string? query) {
		var trimmed = string.IsNullOrEmpty(query) ? string.Empty : (query[0] == '?' ? query[1..] : query);
		if (trimmed.Length == 0) {
			return "?";
		}

		var guarded = EscapeComponentDelimiters(trimmed, isPath: false);
		if (Uri.TryCreate("http://_/?" + guarded, UriKind.Absolute, out var uri)) {
			return CanonicalizeHex("?" + uri.GetComponents(UriComponents.Query, UriFormat.UriEscaped));
		}

		return CanonicalizeHex("?" + guarded);
	}

	// A literal '?', '#', or '\' inside an ALREADY-isolated path/query component is reserved or disallowed
	// (RFC 3986 §2.2/§3.3) and must be percent-encoded. Encode them BEFORE the System.Uri re-parse so the URI
	// parser cannot reinterpret a raw '?'/'#' as a query/fragment delimiter (truncating @path/@query) or fold
	// a '\' to '/'. A literal '?' is valid WITHIN a query, so it is left intact there. This keeps the shared
	// normalizer robust for any caller; the in-box adapters (server ToUriComponent(), client uri.AbsolutePath)
	// already deliver these components pre-isolated and pre-encoded, so this is a no-op on the normal path.
	private static string EscapeComponentDelimiters(string value, bool isPath) {
		var escaped = value.Replace("\\", "%5C").Replace("#", "%23");
		return isPath ? escaped.Replace("?", "%3F") : escaped;
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