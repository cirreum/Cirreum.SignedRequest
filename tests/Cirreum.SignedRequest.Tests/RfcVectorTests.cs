namespace Cirreum.SignedRequest.Tests;

/// <summary>
/// Conformance against published IETF test vectors — pins the cryptographic primitives to the standards'
/// own numbers, not just to our internal known-answer base:
/// <list type="bullet">
///   <item>RFC 4231 §4 — HMAC-SHA-256 test vectors (the algorithm RFC 9421 names <c>hmac-sha256</c>).</item>
///   <item>RFC 9530 Appendix B — <c>Content-Digest</c> (<c>sha-256</c>).</item>
/// </list>
/// </summary>
public sealed class RfcVectorTests {

	private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

	// --- RFC 4231 §4: HMAC-SHA-256 ---

	[Fact]
	public void Rfc4231_test_case_1() {
		// Key = 0x0b x 20, Data = "Hi There".
		var key = new byte[20];
		Array.Fill(key, (byte)0x0b);

		var algorithm = new HmacSha256SignedRequestAlgorithm();
		var signature = algorithm.Sign("Hi There"u8, key);

		Hex(signature).Should().Be("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
		algorithm.Verify("Hi There"u8, signature, key).Should().BeTrue();
	}

	[Fact]
	public void Rfc4231_test_case_2() {
		// Key = "Jefe", Data = "what do ya want for nothing?".
		var signature = new HmacSha256SignedRequestAlgorithm().Sign("what do ya want for nothing?"u8, "Jefe"u8);

		Hex(signature).Should().Be("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	}

	// --- RFC 9530 Appendix B: Content-Digest (sha-256) ---

	[Fact]
	public void Rfc9530_full_representation_digest() {
		// Body: {"hello": "world"} followed by LF (19 bytes) — RFC 9530 Appendix B.1.
		const string expected = "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:";
		var body = "{\"hello\": \"world\"}\n"u8;

		ContentDigest.Compute(body).Should().Be(expected);
		ContentDigest.Verify(expected, body).Should().BeTrue();
	}

	[Fact]
	public void Rfc9530_empty_representation_digest() {
		// Empty body — RFC 9530 Appendix B.2 (the well-known SHA-256 of the empty input).
		const string expected = "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:";

		ContentDigest.Compute([]).Should().Be(expected);
		ContentDigest.Verify(expected, []).Should().BeTrue();
	}
}
