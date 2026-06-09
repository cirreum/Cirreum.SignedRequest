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
	/// this one place (ADR-0021 §8) so the server and client adapters perform mechanical extraction only
	/// and cannot drift. Adapters pass the percent-encoded absolute request path (server
	/// <c>HttpRequest.Path.ToUriComponent()</c>; client <c>Uri.AbsolutePath</c>) and the raw query string;
	/// this uppercases the method, normalizes the query to its RFC 9421 form (leading <c>?</c>; a bare
	/// <c>?</c> when absent), defaults an empty path to <c>/</c>, and stores fields keyed case-insensitively.
	/// </summary>
	public static SignatureBaseComponents FromRequest(
		string method,
		string path,
		string? query,
		IEnumerable<KeyValuePair<string, string>>? fields = null) {

		ArgumentException.ThrowIfNullOrWhiteSpace(method);

		return new SignatureBaseComponents {
			Method = method.ToUpperInvariant(),
			Path = string.IsNullOrEmpty(path) ? "/" : path,
			Query = NormalizeQuery(query),
			Fields = NormalizeFields(fields),
		};
	}

	// RFC 9421 §2.2.7: @query is the query including the leading '?'; no query yields the single char "?".
	private static string NormalizeQuery(string? query) {
		if (string.IsNullOrEmpty(query) || query == "?") {
			return "?";
		}

		return query[0] == '?' ? query : "?" + query;
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