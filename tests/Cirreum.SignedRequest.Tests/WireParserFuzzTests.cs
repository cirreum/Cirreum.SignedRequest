namespace Cirreum.SignedRequest.Tests;

using System.Text;

/// <summary>
/// Fuzz harness for the attacker-controlled parsers. Per RFC 9421 §7 the wire parser MUST return
/// <see langword="false"/> on any malformation and NEVER throw; the same fail-closed, never-throw contract
/// applies to <see cref="ContentDigest.Verify"/>. Drives random and mutated-valid inputs through both with a
/// fixed seed (so a failure is reproducible) and asserts only a boolean ever comes back.
/// </summary>
public sealed class WireParserFuzzTests {

	private const int Iterations = 100_000;

	// Characters chosen to stress the RFC 8941 grammar: quotes, escapes, the list/dict/param delimiters, the
	// byte-sequence colons, the token set, and whitespace.
	private const string Alphabet = "ab01 \t\"\\();:=,@-_.*+/";

	[Fact]
	public void TryParse_never_throws_on_fuzzed_input() {
		var rng = new Random(20260609);
		var valid = ValidSignatureInput();

		for (var i = 0; i < Iterations; i++) {
			var signatureInput = (i % 2 == 0) ? RandomString(rng) : Mutate(rng, valid);
			var signature = (i % 3 == 0) ? Mutate(rng, valid) : RandomString(rng);

			try {
				var parsed = SignatureWireParser.TryParse(signatureInput, signature, out var entries);
				if (parsed && (entries is null || entries.Count == 0)) {
					Assert.Fail($"TryParse returned true with no entries. input=<{signatureInput}> sig=<{signature}>");
				}
			} catch (Exception ex) {
				Assert.Fail($"TryParse threw {ex.GetType().Name} on input=<{signatureInput}> sig=<{signature}>: {ex.Message}");
			}
		}
	}

	[Fact]
	public void ContentDigest_Verify_never_throws_on_fuzzed_input() {
		var rng = new Random(987654321);
		var body = "the request body"u8.ToArray();

		for (var i = 0; i < Iterations; i++) {
			var header = RandomString(rng);
			try {
				ContentDigest.Verify(header, body);
			} catch (Exception ex) {
				Assert.Fail($"ContentDigest.Verify threw {ex.GetType().Name} on header=<{header}>: {ex.Message}");
			}
		}
	}

	private static string RandomString(Random rng) {
		var length = rng.Next(0, 80);
		var sb = new StringBuilder(length);
		for (var i = 0; i < length; i++) {
			sb.Append(Alphabet[rng.Next(Alphabet.Length)]);
		}

		return sb.ToString();
	}

	private static string Mutate(Random rng, string seed) {
		var chars = new List<char>(seed);
		var edits = rng.Next(1, 6);
		for (var e = 0; e < edits && chars.Count > 0; e++) {
			var index = rng.Next(chars.Count);
			switch (rng.Next(3)) {
				case 0: chars.RemoveAt(index); break;
				case 1: chars.Insert(index, Alphabet[rng.Next(Alphabet.Length)]); break;
				default: chars[index] = Alphabet[rng.Next(Alphabet.Length)]; break;
			}
		}

		return new string([.. chars]);
	}

	private static string ValidSignatureInput() {
		var parameters = new SignatureParameters {
			CoveredComponents = ["@method", "@path", "@query", "content-digest"],
			KeyId = "svc-a",
			Algorithm = "hmac-sha256",
			Created = 1_718_000_000,
			Nonce = "nonce-xyz-0123456789",
		};

		return $"sig1={SignatureBaseBuilder.SerializeParameters(parameters)}";
	}
}
