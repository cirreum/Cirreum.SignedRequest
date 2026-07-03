namespace Cirreum.SignedRequest;

using System.Security.Cryptography;

/// <summary>
/// Computes and verifies the SHA-256 <c>Content-Digest</c> value (RFC 9530) that binds a request body into a
/// SignedRequest signature regardless of method (resolving the unsigned-DELETE-body class). Pure.
/// </summary>
/// <remarks>
/// This is a SignedRequest helper, <b>not</b> a general-purpose Content-Digest / RFC 8941 implementation: it
/// supports the canonical byte-sequence form (<c>sha-256=:&lt;base64&gt;:</c>) Cirreum signers emit, plus
/// harmless transport variation (member parameters, surrounding whitespace, a case-insensitive key). Don't
/// reuse it as a generic structured-field parser.
/// </remarks>
public static class ContentDigest {

	/// <summary>The SHA-256 digest algorithm key in a Content-Digest dictionary field.</summary>
	public const string Sha256Key = "sha-256";

	/// <summary>
	/// Computes the <c>Content-Digest</c> field value for a body: <c>sha-256=:&lt;base64&gt;:</c>.
	/// </summary>
	public static string Compute(ReadOnlySpan<byte> body) {
		Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
		SHA256.HashData(body, hash);
		return $"{Sha256Key}=:{Convert.ToBase64String(hash)}:";
	}

	/// <summary>
	/// Verifies that a received <c>Content-Digest</c> field value contains a SHA-256 digest matching
	/// <paramref name="body"/>, in constant time. Returns <see langword="false"/> for a malformed value
	/// or a missing SHA-256 entry.
	/// </summary>
	/// <remarks>
	/// Accepts the canonical RFC 9530 form <c>sha-256=:&lt;base64&gt;:</c> within an RFC 8941 dictionary,
	/// tolerating trailing member parameters (e.g. <c>sha-256=:…:;x=1</c>) and matching the <c>sha-256</c> key
	/// case-insensitively (the digest must still match the body, so a forgiving key is harmless). This is not a
	/// general structured-field parser: other algorithm keys are skipped, and a malformed <c>sha-256</c> member
	/// fails rather than falling through to a duplicate.
	/// </remarks>
	public static bool Verify(string? headerValue, ReadOnlySpan<byte> body) {
		if (string.IsNullOrWhiteSpace(headerValue)) {
			return false;
		}

		// Cirreum SignedRequest emits the canonical byte-sequence member; this is intentionally not a general
		// RFC 8941 parser. base64 contains no comma, so splitting dictionary members on ',' is safe here. We scan
		// ALL members and require EXACTLY ONE sha-256 entry: RFC 8941 §3.2 forbids duplicate dictionary keys, so a
		// repeated sha-256 member (which a general parser would resolve last-wins, diverging from this code's
		// first-wins) fails closed rather than letting two implementations disagree on the authoritative digest (G4).
		string? sha256Value = null;
		foreach (var member in headerValue.Split(',')) {
			var entry = member.Trim();
			var eq = entry.IndexOf('=');
			if (eq <= 0) {
				continue;
			}

			var key = entry[..eq].Trim();
			if (!key.Equals(Sha256Key, StringComparison.OrdinalIgnoreCase)) {
				continue;
			}

			if (sha256Value is not null) {
				return false; // a second sha-256 member — duplicate dictionary key.
			}

			sha256Value = entry[(eq + 1)..].Trim();
		}

		if (sha256Value is null) {
			return false;
		}

		// RFC 8941 byte sequence: ':' base64 ':', optionally followed by ;parameters (which we ignore).
		if (sha256Value.Length < 2 || sha256Value[0] != ':') {
			return false;
		}

		var close = sha256Value.IndexOf(':', 1);
		if (close < 0) {
			return false;
		}

		var trailer = sha256Value[(close + 1)..].TrimStart();
		if (trailer.Length > 0 && trailer[0] != ';') {
			return false;
		}

		if (!TryFromBase64(sha256Value[1..close], out var expected) || expected.Length != SHA256.HashSizeInBytes) {
			return false;
		}

		Span<byte> actual = stackalloc byte[SHA256.HashSizeInBytes];
		SHA256.HashData(body, actual);
		return CryptographicOperations.FixedTimeEquals(actual, expected);
	}

	private static bool TryFromBase64(string value, out byte[] bytes) {
		if (value.Length is 0 or > 256) {
			bytes = [];
			return false;
		}

		var buffer = new byte[((value.Length + 3) / 4) * 3];
		if (Convert.TryFromBase64String(value, buffer, out var written)) {
			bytes = buffer[..written];
			return true;
		}

		bytes = [];
		return false;
	}

}
