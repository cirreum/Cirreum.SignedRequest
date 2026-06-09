namespace Cirreum.SignedRequest;

/// <summary>
/// Defensively parses the RFC 9421 <c>Signature</c> and <c>Signature-Input</c> headers into
/// <see cref="ParsedSignature"/> entries (a focused RFC 8941 subset: a dictionary whose members are an
/// inner list of strings with parameters, paired with a byte-sequence signature). All inputs are
/// attacker-controlled, so every malformation returns <see langword="false"/> — this never throws
/// (ADR-0021 §7).
/// </summary>
public static class SignatureWireParser {

	private const int MaxSignatureBytes = 1024;
	private const int MaxHeaderLength = 8192;

	/// <summary>
	/// Parses the headers into the signatures they describe. Returns <see langword="false"/> on any
	/// malformation, a missing <c>Signature</c> entry for a labelled input, or a missing required
	/// parameter (<c>created</c>, <c>keyid</c>, <c>alg</c>).
	/// </summary>
	public static bool TryParse(string? signatureInput, string? signature, out IReadOnlyList<ParsedSignature> entries) {
		entries = [];

		if (string.IsNullOrWhiteSpace(signatureInput) || string.IsNullOrWhiteSpace(signature)) {
			return false;
		}

		// Bound total parsing work against oversized attacker-supplied headers (defense-in-depth above
		// the host's header-size limit).
		if (signatureInput.Length > MaxHeaderLength || signature.Length > MaxHeaderLength) {
			return false;
		}

		if (!TryParseDictionary(signatureInput, out var inputMembers)
			|| !TryParseDictionary(signature, out var signatureMembers)) {
			return false;
		}

		var signatureMap = new Dictionary<string, string>(StringComparer.Ordinal);
		foreach (var (sigLabel, sigRaw) in signatureMembers) {
			signatureMap[sigLabel] = sigRaw;
		}

		var result = new List<ParsedSignature>(inputMembers.Count);

		foreach (var (label, paramsValue) in inputMembers) {
			if (!signatureMap.TryGetValue(label, out var sigValue)) {
				return false;
			}

			if (!TryParseSignatureBytes(sigValue, out var sigBytes)) {
				return false;
			}

			if (!TryParseParamsValue(paramsValue, out var covered, out var pmap)) {
				return false;
			}

			if (!pmap.TryGetValue("created", out var createdRaw) || !TryParseInteger(createdRaw, out var created)
				|| !pmap.TryGetValue("keyid", out var keyIdRaw) || !TryParseSfString(keyIdRaw, out var keyId)
				|| !pmap.TryGetValue("alg", out var algRaw) || !TryParseSfString(algRaw, out var alg)) {
				return false;
			}

			long? expires = null;
			if (pmap.TryGetValue("expires", out var expiresRaw)) {
				if (!TryParseInteger(expiresRaw, out var e)) {
					return false;
				}

				expires = e;
			}

			string? nonce = null;
			if (pmap.TryGetValue("nonce", out var nonceRaw) && !TryParseSfString(nonceRaw, out nonce)) {
				return false;
			}

			string? tag = null;
			if (pmap.TryGetValue("tag", out var tagRaw) && !TryParseSfString(tagRaw, out tag)) {
				return false;
			}

			result.Add(new ParsedSignature {
				Label = label,
				CoveredComponents = covered,
				SignatureParamsValue = paramsValue,
				Created = created,
				Expires = expires,
				KeyId = keyId,
				Algorithm = alg,
				Nonce = nonce,
				Tag = tag,
				Signature = sigBytes,
			});
		}

		entries = result;
		return result.Count > 0;
	}

	// Splits an RFC 8941 dictionary into ordered (label -> raw value) members, honoring quoted strings.
	private static bool TryParseDictionary(string input, out List<(string Label, string Value)> members) {
		members = [];
		var seen = new HashSet<string>(StringComparer.Ordinal);

		foreach (var raw in SplitTopLevel(input, ',')) {
			var member = raw.Trim();
			if (member.Length == 0) {
				return false;
			}

			var eq = member.IndexOf('=');
			if (eq <= 0 || eq == member.Length - 1) {
				return false;
			}

			var label = member[..eq].Trim();
			if (label.Length == 0 || !IsToken(label)) {
				return false;
			}

			// Reject duplicate dictionary labels (defensive — no silent last-wins).
			if (!seen.Add(label)) {
				return false;
			}

			members.Add((label, member[(eq + 1)..].Trim()));
		}

		return members.Count > 0;
	}

	// Parses "(<inner list>)<params>" into the covered components and a parameter map (raw values).
	private static bool TryParseParamsValue(
		string value,
		out IReadOnlyList<string> covered,
		out Dictionary<string, string> parameters) {

		covered = [];
		parameters = new Dictionary<string, string>(StringComparer.Ordinal);

		if (value.Length == 0 || value[0] != '(') {
			return false;
		}

		var close = FindMatchingListClose(value);
		if (close < 0) {
			return false;
		}

		var inner = value[1..close];
		var list = new List<string>();
		foreach (var item in SplitTopLevel(inner, ' ')) {
			var trimmed = item.Trim();
			if (trimmed.Length == 0) {
				continue;
			}

			if (!TryParseSfString(trimmed, out var component)) {
				return false;
			}

			list.Add(component);
		}

		// An empty covered-component list "()" signs nothing about the request (only @signature-params),
		// which is meaningless for request authentication — reject it rather than let a consumer that cleared
		// RequiredCoveredComponents accept a request-unbound signature.
		if (list.Count == 0) {
			return false;
		}

		covered = list;

		var rest = value[(close + 1)..];
		foreach (var part in SplitTopLevel(rest, ';')) {
			var p = part.Trim();
			if (p.Length == 0) {
				continue;
			}

			var eq = p.IndexOf('=');
			if (eq <= 0) {
				return false;
			}

			var key = p[..eq].Trim();
			if (!IsToken(key)) {
				return false;
			}

			// Reject duplicate parameters (defensive — prevents silent last-wins downgrade of alg/keyid/created).
			if (!parameters.TryAdd(key, p[(eq + 1)..].Trim())) {
				return false;
			}
		}

		return true;
	}

	private static bool TryParseSignatureBytes(string value, out byte[] bytes) {
		bytes = [];

		if (value.Length < 2 || value[0] != ':' || value[^1] != ':') {
			return false;
		}

		var b64 = value[1..^1];
		if (b64.Length is 0 or > (MaxSignatureBytes * 4 / 3 + 4)) {
			return false;
		}

		var buffer = new byte[((b64.Length + 3) / 4) * 3];
		if (!Convert.TryFromBase64String(b64, buffer, out var written) || written is 0 or > MaxSignatureBytes) {
			return false;
		}

		bytes = buffer[..written];
		return true;
	}

	private static bool TryParseSfString(string value, out string result) {
		result = string.Empty;

		if (value.Length < 2 || value[0] != '"' || value[^1] != '"') {
			return false;
		}

		var sb = new System.Text.StringBuilder(value.Length - 2);
		for (var i = 1; i < value.Length - 1; i++) {
			var c = value[i];
			if (c == '\\') {
				i++;
				if (i >= value.Length - 1) {
					return false;
				}

				var next = value[i];
				if (next is not ('\\' or '"')) {
					return false;
				}

				sb.Append(next);
			} else if (c is '"') {
				return false;
			} else {
				sb.Append(c);
			}
		}

		result = sb.ToString();
		return true;
	}

	// RFC 8941 sf-integer permits only a leading '-' (never '+'); and created/expires must be a Unix-seconds
	// value the consumers can hand to DateTimeOffset.FromUnixTimeSeconds without throwing. Enforce both here,
	// at the single integer choke point, so an out-of-range-but-valid long can never reach an unguarded
	// FromUnixTimeSeconds downstream (which would otherwise surface as an unhandled 500 on attacker input).
	private const long MinUnixSeconds = -62135596800; // DateTimeOffset.MinValue, whole seconds
	private const long MaxUnixSeconds = 253402300799;  // DateTimeOffset.MaxValue, whole seconds

	private static bool TryParseInteger(string value, out long result) {
		result = 0;
		if (value.StartsWith('+')) {
			return false;
		}

		return long.TryParse(value, System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out result)
			&& result is >= MinUnixSeconds and <= MaxUnixSeconds;
	}

	private static int FindMatchingListClose(string value) {
		var inString = false;
		var escaped = false;

		for (var i = 1; i < value.Length; i++) {
			var c = value[i];
			if (inString) {
				if (escaped) {
					escaped = false;
				} else if (c == '\\') {
					escaped = true;
				} else if (c == '"') {
					inString = false;
				}
			} else if (c == '"') {
				inString = true;
			} else if (c == ')') {
				return i;
			} else if (c == '(') {
				return -1;
			}
		}

		return -1;
	}

	private static List<string> SplitTopLevel(string value, char separator) {
		var parts = new List<string>();
		var start = 0;
		var inString = false;
		var escaped = false;

		for (var i = 0; i < value.Length; i++) {
			var c = value[i];
			if (inString) {
				if (escaped) {
					escaped = false;
				} else if (c == '\\') {
					escaped = true;
				} else if (c == '"') {
					inString = false;
				}
			} else if (c == '"') {
				inString = true;
			} else if (c == separator) {
				parts.Add(value[start..i]);
				start = i + 1;
			}
		}

		parts.Add(value[start..]);
		return parts;
	}

	private static bool IsToken(string value) {
		foreach (var c in value) {
			if (!char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.' or '*')) {
				return false;
			}
		}

		return value.Length > 0;
	}

}
