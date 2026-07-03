namespace Cirreum.SignedRequest;

using System.Text;

/// <summary>
/// The shared HMAC signing-secret strength floor (NIST SP 800-107). One definition used by the server
/// resolver (verify), the standalone webhook validator (verify), and the outbound signers (sign), so the
/// secret-strength gate is consistent across every surface rather than enforced on one and silently absent on
/// another.
/// </summary>
/// <remarks>
/// The floor counts UTF-8 <em>bytes</em> of the secret string, not entropy: a 16-byte secret is the 128-bit
/// security floor only when those bytes are random. NIST SP 800-107 §5.3.4 recommends a key at least the hash
/// output (32 bytes) for full strength — provision a high-entropy secret (e.g. via
/// <see cref="SigningSecretGenerator"/>) rather than a short passphrase.
/// </remarks>
public static class SignedRequestSecret {

	/// <summary>The minimum signing-secret length in UTF-8 bytes (the 128-bit floor for a random secret).</summary>
	public const int MinimumBytes = 16;

	/// <summary>Whether <paramref name="secret"/> meets the <see cref="MinimumBytes"/> floor.</summary>
	public static bool MeetsFloor(string? secret) =>
		!string.IsNullOrEmpty(secret) && Encoding.UTF8.GetByteCount(secret) >= MinimumBytes;

	/// <summary>
	/// Throws when <paramref name="secret"/> is below the floor — for the signing (emit) side, where a weak key
	/// should fail fast at development time rather than produce a structurally weak signature.
	/// </summary>
	public static void EnsureFloor(string secret, string paramName) {
		if (!MeetsFloor(secret)) {
			throw new ArgumentException(
				$"The signing secret must be at least {MinimumBytes} bytes (ideally >= 32 random bytes; NIST SP 800-107). " +
				"Provision a high-entropy secret (see SigningSecretGenerator) rather than a short passphrase.", paramName);
		}
	}
}
