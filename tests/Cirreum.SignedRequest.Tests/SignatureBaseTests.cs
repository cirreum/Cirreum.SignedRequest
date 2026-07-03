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

	// --- ① Path/query canonicalization: a path/query extracted differently on each side (client
	//        Uri.AbsolutePath, server ToUriComponent(), or a raw relative target) still yields the
	//        byte-identical value (RFC 9421 §2.2.6/§2.2.7 + RFC 3986 §6.2.2). ---

	[Theory]
	[InlineData("/files/a%20b", "/files/a b")]   // percent-encoded vs literal space
	[InlineData("/a%2fb", "/a%2Fb")]             // percent-hex case
	[InlineData("/%7euser", "/~user")]           // encoded vs decoded unreserved octet
	[InlineData("/a/../b", "/b")]                // resolved dot-segments
	public void FromRequest_canonicalizes_divergent_path_encodings_to_one_value(string left, string right) {
		SignatureBaseComponents.FromRequest("GET", left, null).Path
			.Should().Be(SignatureBaseComponents.FromRequest("GET", right, null).Path);
	}

	[Theory]
	[InlineData("?x=%2f", "?x=%2F")]             // percent-hex case in the query
	[InlineData("q=a%20b", "?q=a%20b")]          // leading '?' normalization preserves encoding
	public void FromRequest_canonicalizes_divergent_query_encodings_to_one_value(string left, string right) {
		SignatureBaseComponents.FromRequest("GET", "/x", left).Query
			.Should().Be(SignatureBaseComponents.FromRequest("GET", "/x", right).Query);
	}

	[Fact]
	public void FromRequest_uppercases_percent_hex_to_the_RFC_3986_canonical_form() {
		SignatureBaseComponents.FromRequest("GET", "/a%2fb", null).Path.Should().Be("/a%2Fb");
	}

	[Fact]
	public void FromRequest_binds_dot_segment_paths_to_the_canonical_target() {
		// Policy (A4): @path is RFC 3986 §5.2.4 normalized, so two spellings of the same resource collapse to
		// one canonical target. This collision is INTENTIONAL — the signature binds the resource the ASP.NET
		// pipeline routes/authorizes on, not a particular spelling — so a traversal spelling cannot reach a
		// DIFFERENT endpoint under a signature valid for one, and authorization keys on the normalized path.
		var traversalSpelling = SignatureBaseComponents.FromRequest("GET", "/public/../admin", null).Path;
		var canonicalTarget = SignatureBaseComponents.FromRequest("GET", "/admin", null).Path;

		traversalSpelling.Should().Be("/admin");
		traversalSpelling.Should().Be(canonicalTarget);
	}

	// --- Canonicalization robustness (A1/A3): a raw '?', '#', or '\' in an already-isolated component must be
	//     percent-encoded, NOT reinterpreted by System.Uri as a query/fragment delimiter (truncating the
	//     component) or folded ('\'→'/'). Two distinct targets must never collapse to one signature base. ---

	[Theory]
	[InlineData("/a?b=c", "/a%3Fb=c")]   // literal '?' encoded, not a query delimiter (no @path truncation)
	[InlineData("/a#frag", "/a%23frag")] // literal '#' encoded, not a fragment delimiter
	[InlineData("/a\\b", "/a%5Cb")]      // backslash encoded, not folded to '/'
	public void FromRequest_does_not_let_a_raw_delimiter_truncate_or_fold_the_path(string path, string expected) {
		SignatureBaseComponents.FromRequest("GET", path, null).Path.Should().Be(expected);
	}

	[Fact]
	public void FromRequest_does_not_let_a_raw_hash_truncate_the_query() {
		SignatureBaseComponents.FromRequest("GET", "/x", "a=b#c").Query.Should().Be("?a=b%23c");
	}

	[Fact]
	public void FromRequest_keeps_distinct_delimiter_targets_distinct() {
		// '/a?b' (a path literally containing '?') must NOT collide with '/a' (path with a 'b' query).
		var withLiteralQuestion = SignatureBaseComponents.FromRequest("GET", "/a?b", null).Path;
		var rootWithQuery = SignatureBaseComponents.FromRequest("GET", "/a", "b").Path;

		withLiteralQuestion.Should().Be("/a%3Fb");
		rootWithQuery.Should().Be("/a");
		withLiteralQuestion.Should().NotBe(rootWithQuery);
	}

	// --- ② Parser hardening: attacker-controlled timestamps never throw, and degenerate params fail closed ---

	private static readonly string SampleSignature = $"sig1=:{Convert.ToBase64String([1, 2, 3, 4])}:";

	[Theory]
	[InlineData("253402300800")]            // one second past DateTimeOffset.MaxValue
	[InlineData("99999999999999999999")]    // overflows Int64
	[InlineData("-62135596801")]            // one second before DateTimeOffset.MinValue
	public void TryParse_rejects_an_out_of_range_created_without_throwing(string created) {
		var input = $"sig1=(\"@method\");created={created};keyid=\"k\";alg=\"hmac-sha256\"";

		var act = () => SignatureWireParser.TryParse(input, SampleSignature, out _);

		act.Should().NotThrow();
		SignatureWireParser.TryParse(input, SampleSignature, out _).Should().BeFalse();
	}

	[Fact]
	public void TryParse_rejects_a_leading_plus_on_created() {
		var input = "sig1=(\"@method\");created=+1718000000;keyid=\"k\";alg=\"hmac-sha256\"";

		SignatureWireParser.TryParse(input, SampleSignature, out _).Should().BeFalse();
	}

	[Fact]
	public void TryParse_rejects_an_empty_covered_component_list() {
		var input = "sig1=();created=1718000000;keyid=\"k\";alg=\"hmac-sha256\"";

		SignatureWireParser.TryParse(input, SampleSignature, out _).Should().BeFalse();
	}

	[Fact]
	public void TryParse_rejects_duplicate_covered_components_G1() {
		// RFC 9421 §2.3: a covered component identifier must not appear more than once.
		var input = "sig1=(\"@method\" \"@method\");created=1718000000;keyid=\"k\";alg=\"hmac-sha256\"";

		SignatureWireParser.TryParse(input, SampleSignature, out _).Should().BeFalse();
	}

	[Fact]
	public void TryParse_rejects_a_non_lowercase_field_component_G2() {
		// RFC 9421 §2.1: HTTP field component identifiers are lowercase; a mixed-case field name is rejected so
		// the coverage check and the content-digest gate cannot disagree.
		var input = "sig1=(\"@method\" \"Content-Digest\");created=1718000000;keyid=\"k\";alg=\"hmac-sha256\"";

		SignatureWireParser.TryParse(input, SampleSignature, out _).Should().BeFalse();
	}

	[Fact]
	public void ContentDigest_verify_rejects_duplicate_sha256_members_G4() {
		var body = "hi"u8.ToArray();
		var digest = ContentDigest.Compute(body);

		ContentDigest.Verify(digest + "," + digest, body).Should().BeFalse("RFC 8941 §3.2 forbids duplicate dictionary keys");
	}

	[Fact]
	public void TryParse_rejects_an_empty_keyid_C4() {
		// keyid is the credential selector / implicit audience; an empty one is not a meaningful reference and
		// must be rejected at the parser chokepoint so a naive store cannot treat it as match-anything.
		var input = "sig1=(\"@method\");created=1718000000;keyid=\"\";alg=\"hmac-sha256\"";

		SignatureWireParser.TryParse(input, SampleSignature, out _).Should().BeFalse();
	}

	[Fact]
	public void TryParse_accepts_a_well_formed_signature_at_the_timestamp_boundary() {
		var input = "sig1=(\"@method\");created=253402300799;keyid=\"k\";alg=\"hmac-sha256\"";

		SignatureWireParser.TryParse(input, SampleSignature, out var entries).Should().BeTrue();
		entries.Should().ContainSingle().Which.Created.Should().Be(253402300799);
	}

	// --- Known-answer vector: locks the exact RFC 9421 wire signature base byte-for-byte, so the server
	//     scheme and the client SDK (which carry their own copy of these vectors) cannot drift. ---

	[Fact]
	public void Known_answer_signature_base_is_byte_stable() {
		var components = SignatureBaseComponents.FromRequest(
			"POST", "/api/orders", "?page=1", [new("content-digest", "sha-256=:abc:")]);

		var signed = SignatureBaseBuilder.BuildForSigning(components, Params());

		var expected =
			"\"@method\": POST\n" +
			"\"@path\": /api/orders\n" +
			"\"@query\": ?page=1\n" +
			"\"content-digest\": sha-256=:abc:\n" +
			"\"@signature-params\": (\"@method\" \"@path\" \"@query\" \"content-digest\")" +
			";created=1718000000;keyid=\"svc-a\";alg=\"hmac-sha256\";nonce=\"nonce-xyz-0123456789\"";

		System.Text.Encoding.UTF8.GetString(signed.SignatureBase).Should().Be(expected);
	}

}
