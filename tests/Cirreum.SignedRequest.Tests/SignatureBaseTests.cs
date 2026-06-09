namespace Cirreum.SignedRequest.Tests;


public sealed class SignatureBaseTests {

	private static SignatureParameters Params(params string[] covered) =>
		new() {
			CoveredComponents = covered.Length > 0 ? covered : ["@method", "@path", "@query", "content-digest"],
			KeyId = "svc-a",
			Algorithm = "hmac-sha256",
			Created = 1_718_000_000,
			Nonce = "nonce-xyz-0123456789",
		};

	// --- FromRequest: the single shared normalizer (ADR-0021 §8) ---

	[Fact]
	public void FromRequest_uppercases_the_method() {
		SignatureBaseComponents.FromRequest("get", "/x", null).Method.Should().Be("GET");
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("?")]
	public void FromRequest_normalizes_an_absent_query_to_a_bare_question_mark(string? query) {
		SignatureBaseComponents.FromRequest("GET", "/x", query).Query.Should().Be("?");
	}

	[Fact]
	public void FromRequest_prepends_the_question_mark_when_the_query_omits_it() {
		SignatureBaseComponents.FromRequest("GET", "/x", "a=1&b=2").Query.Should().Be("?a=1&b=2");
	}

	[Fact]
	public void FromRequest_preserves_a_query_that_already_has_the_leading_question_mark() {
		SignatureBaseComponents.FromRequest("GET", "/x", "?a=1").Query.Should().Be("?a=1");
	}

	[Fact]
	public void FromRequest_defaults_an_empty_path_to_root() {
		SignatureBaseComponents.FromRequest("GET", "", null).Path.Should().Be("/");
	}

	[Fact]
	public void FromRequest_stores_fields_case_insensitively() {
		var components = SignatureBaseComponents.FromRequest(
			"GET", "/x", null, [new("Content-Digest", "sha-256=:abc:")]);

		components.Fields.TryGetValue("content-digest", out var value).Should().BeTrue();
		value.Should().Be("sha-256=:abc:");
	}

	[Fact]
	public void FromRequest_throws_on_a_blank_method() {
		var act = () => SignatureBaseComponents.FromRequest("  ", "/x", null);

		act.Should().Throw<ArgumentException>();
	}

	// --- The point of §8: server-style and client-style extraction yield a byte-identical base ---

	[Fact]
	public void Server_and_client_extraction_styles_produce_a_byte_identical_signature_base() {
		var fields = new Dictionary<string, string> { ["content-digest"] = "sha-256=:abc:" };

		// Server adapter: ASP.NET hands an uppercase method and an empty QueryString for no-query.
		var server = SignatureBaseComponents.FromRequest("GET", "/api/orders", "", fields);
		// Client adapter: HttpClient hands a lowercase method (caller error) and a null Uri.Query.
		var client = SignatureBaseComponents.FromRequest("get", "/api/orders", null, fields);

		var parameters = Params();
		var serverBase = SignatureBaseBuilder.BuildForSigning(server, parameters).SignatureBase;
		var clientBase = SignatureBaseBuilder.BuildForSigning(client, parameters).SignatureBase;

		clientBase.Should().Equal(serverBase);
	}

	// --- Signer/verifier symmetry: BuildBase over the serialized params reproduces the signing base ---

	[Fact]
	public void BuildBase_reproduces_the_signing_base_from_the_serialized_params() {
		var components = SignatureBaseComponents.FromRequest(
			"POST", "/api/orders", "?page=1", [new("content-digest", "sha-256=:abc:")]);
		var parameters = Params();

		var signed = SignatureBaseBuilder.BuildForSigning(components, parameters);
		var rebuilt = SignatureBaseBuilder.BuildBase(
			components, parameters.CoveredComponents, signed.SignatureParamsValue);

		rebuilt.Should().Equal(signed.SignatureBase);
	}

	// --- @authority is dropped (ADR-0021 2026-06-08): it is no longer a recognized component ---

	[Fact]
	public void Authority_is_rejected_as_an_unsupported_derived_component() {
		var components = SignatureBaseComponents.FromRequest("GET", "/x", null);

		var act = () => SignatureBaseBuilder.BuildBase(components, ["@authority"], "()");

		act.Should().Throw<InvalidOperationException>().WithMessage("*Unsupported derived signature component*");
	}

	// --- Wire round-trip: serialized params parse back to identical components + parameters ---

	[Fact]
	public void Serialized_params_round_trip_through_the_wire_parser() {
		var parameters = Params();
		var paramsValue = SignatureBaseBuilder.SerializeParameters(parameters);

		var signatureInput = $"sig1={paramsValue}";
		var signature = $"sig1=:{Convert.ToBase64String([1, 2, 3, 4])}:";

		SignatureWireParser.TryParse(signatureInput, signature, out var entries).Should().BeTrue();

		var entry = entries.Should().ContainSingle().Which;
		entry.CoveredComponents.Should().Equal("@method", "@path", "@query", "content-digest");
		entry.KeyId.Should().Be("svc-a");
		entry.Algorithm.Should().Be("hmac-sha256");
		entry.Created.Should().Be(1_718_000_000);
		entry.Nonce.Should().Be("nonce-xyz-0123456789");
		entry.SignatureParamsValue.Should().Be(paramsValue);
	}

	// --- Content-Digest binds the body (RFC 9530), including the empty body for bodyless methods ---

	[Fact]
	public void ContentDigest_compute_then_verify_round_trips() {
		var body = "hello world"u8.ToArray();

		ContentDigest.Verify(ContentDigest.Compute(body), body).Should().BeTrue();
	}

	[Fact]
	public void ContentDigest_verify_rejects_a_tampered_body() {
		var digest = ContentDigest.Compute("hello"u8);

		ContentDigest.Verify(digest, "hellp"u8).Should().BeFalse();
	}

	[Fact]
	public void ContentDigest_binds_the_empty_body() {
		ContentDigest.Verify(ContentDigest.Compute([]), []).Should().BeTrue();
	}

}
