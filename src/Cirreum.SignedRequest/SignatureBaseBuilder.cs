namespace Cirreum.SignedRequest;

using System.Text;

/// <summary>
/// Builds the RFC 9421 HTTP Message Signatures signature base — the single, shared construction used
/// by both the server verifier and the client/outbound signer (ADR-0021 §8), so they can never drift.
/// Pure: no ASP.NET or <c>HttpClient</c> dependency.
/// </summary>
/// <remarks>
/// The signature base is the newline-joined sequence of <c>"component": value</c> lines for each
/// covered component, terminated by the <c>"@signature-params": &lt;params&gt;</c> line (no trailing
/// newline). On the verify side, the <em>received</em> signature-params value is passed verbatim so the
/// reconstructed base is byte-identical to what was signed.
/// </remarks>
public static class SignatureBaseBuilder {

	/// <summary>
	/// Builds the signing-side signature base and the serialized signature-params value from the
	/// neutral components and parameters.
	/// </summary>
	public static SignatureBaseResult BuildForSigning(SignatureBaseComponents components, SignatureParameters parameters) {
		ArgumentNullException.ThrowIfNull(components);
		ArgumentNullException.ThrowIfNull(parameters);

		var paramsValue = SerializeParameters(parameters);
		var baseBytes = BuildBase(components, parameters.CoveredComponents, paramsValue);
		return new SignatureBaseResult(baseBytes, paramsValue);
	}

	/// <summary>
	/// Builds the signature base bytes from the neutral components, the covered-component list, and the
	/// (verbatim) signature-params value. The verify side passes the value parsed from the request's
	/// <c>Signature-Input</c> header so the base matches exactly.
	/// </summary>
	public static byte[] BuildBase(
		SignatureBaseComponents components,
		IReadOnlyList<string> coveredComponents,
		string signatureParamsValue) {

		ArgumentNullException.ThrowIfNull(components);
		ArgumentNullException.ThrowIfNull(coveredComponents);
		ArgumentException.ThrowIfNullOrEmpty(signatureParamsValue);

		var builder = new StringBuilder();

		foreach (var component in coveredComponents) {
			// Serialize the component name with the SAME sf-string routine the @signature-params trailer uses, so
			// each base line's name is byte-identical to its appearance in the verbatim params (G5). For all valid
			// (lowercase / @-derived) names this is the plain quoted form; it closes a latent decode/re-encode
			// asymmetry if an escaped name is ever admitted.
			AppendSfString(builder, component);
			builder.Append(": ").Append(ComponentValue(component, components)).Append('\n');
		}

		builder.Append("\"@signature-params\": ").Append(signatureParamsValue);

		return Encoding.UTF8.GetBytes(builder.ToString());
	}

	/// <summary>
	/// Serializes the signature-params value (RFC 8941 inner list of covered components + parameters).
	/// </summary>
	public static string SerializeParameters(SignatureParameters parameters) {
		ArgumentNullException.ThrowIfNull(parameters);

		var builder = new StringBuilder();

		builder.Append('(');
		for (var i = 0; i < parameters.CoveredComponents.Count; i++) {
			if (i > 0) {
				builder.Append(' ');
			}

			AppendSfString(builder, parameters.CoveredComponents[i]);
		}

		builder.Append(')');

		builder.Append(";created=").Append(parameters.Created);
		if (parameters.Expires is { } expires) {
			builder.Append(";expires=").Append(expires);
		}

		builder.Append(";keyid=");
		AppendSfString(builder, parameters.KeyId);
		builder.Append(";alg=");
		AppendSfString(builder, parameters.Algorithm);

		if (!string.IsNullOrEmpty(parameters.Nonce)) {
			builder.Append(";nonce=");
			AppendSfString(builder, parameters.Nonce);
		}

		if (!string.IsNullOrEmpty(parameters.Tag)) {
			builder.Append(";tag=");
			AppendSfString(builder, parameters.Tag);
		}

		return builder.ToString();
	}

	private static string ComponentValue(string component, SignatureBaseComponents components) {
		switch (component) {
			case SignatureComponentNames.Method:
				return components.Method;
			case SignatureComponentNames.Path:
				return components.Path;
			case SignatureComponentNames.Query:
				return components.Query;
			default:
				if (component.StartsWith('@')) {
					throw new InvalidOperationException($"Unsupported derived signature component '{component}'.");
				}

				return components.Fields.TryGetValue(component, out var value)
					? value
					: throw new InvalidOperationException(
						$"The '{component}' field is covered by the signature but is absent from the request.");
		}
	}

	// RFC 8941 sf-string: DQUOTE-wrapped, with '\' and '"' backslash-escaped.
	private static void AppendSfString(StringBuilder builder, string value) {
		builder.Append('"');
		foreach (var c in value) {
			if (c is '\\' or '"') {
				builder.Append('\\');
			}

			builder.Append(c);
		}

		builder.Append('"');
	}

}
