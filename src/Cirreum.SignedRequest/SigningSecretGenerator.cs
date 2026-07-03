namespace Cirreum.SignedRequest;

using System.Security.Cryptography;

/// <summary>
/// Generates a high-entropy HMAC signing secret — the recommended provisioning path so a (self-service)
/// credential's secret is a CSPRNG key rather than an operator-chosen passphrase (E2). Mirrors the ApiKey
/// generator: cryptographically random bytes, URL-safe Base64 (no padding), safe in JSON / headers / config.
/// </summary>
public static class SigningSecretGenerator {

	/// <summary>The default secret size in bytes — the SHA-256 output size NIST SP 800-107 recommends for full HMAC strength.</summary>
	public const int DefaultBytes = 32;

	/// <summary>
	/// Generates a URL-safe Base64 (unpadded) signing secret of <paramref name="bytes"/> cryptographically
	/// random bytes. Values below <see cref="SignedRequestSecret.MinimumBytes"/> are raised to it so the result
	/// always clears the verification floor.
	/// </summary>
	public static string Generate(int bytes = DefaultBytes) {
		var size = Math.Max(bytes, SignedRequestSecret.MinimumBytes);
		var buffer = new byte[size];
		RandomNumberGenerator.Fill(buffer);

		return Convert.ToBase64String(buffer)
			.Replace('+', '-')
			.Replace('/', '_')
			.TrimEnd('=');
	}
}
