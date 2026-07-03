namespace Cirreum.SignedRequest.Tests;

using System.Net.Http;
using System.Text;

/// <summary>
/// Home-package coverage for the outbound signer (<see cref="HttpRequestMessageSigningExtensions"/>), which
/// lives in Cirreum.SignedRequest so the server scheme and the client SDK share one implementation. Verifies
/// the emitted signature reconstructs and validates using only Common primitives (parser + builder + algorithm
/// + Content-Digest) — the same path any verifier walks.
/// </summary>
public sealed class OutboundSignerTests {

	private const string KeyId = "svc-a";
	private const string Secret = "super-secret-signing-key";

	private static HttpRequestMessage NewRequest(string uri = "https://api.example.com/orders?page=1", string? body = "{\"id\":1}") {
		var request = new HttpRequestMessage(HttpMethod.Post, uri);
		if (body is not null) {
			request.Content = new StringContent(body, Encoding.UTF8, "application/json");
		}

		return request;
	}

	private static bool VerifyWithCommonPrimitives(HttpRequestMessage request, string secret) {
		var body = request.Content is null ? [] : request.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
		string Header(string name) => request.Headers.TryGetValues(name, out var v) ? string.Join(",", v) : string.Empty;

		if (!SignatureWireParser.TryParse(Header(SignedRequestHeaders.SignatureInput), Header(SignedRequestHeaders.Signature), out var entries) || entries.Count != 1) {
			return false;
		}

		var entry = entries[0];
		var uri = request.RequestUri!;
		var fields = new Dictionary<string, string> { [SignatureComponentNames.ContentDigest] = Header(SignedRequestHeaders.ContentDigest) };
		var components = SignatureBaseComponents.FromRequest(request.Method.Method, uri.AbsolutePath, uri.Query, fields);
		var signatureBase = SignatureBaseBuilder.BuildBase(components, entry.CoveredComponents, entry.SignatureParamsValue);

		return new HmacSha256SignedRequestAlgorithm().Verify(signatureBase, entry.Signature, Encoding.UTF8.GetBytes(secret))
			&& ContentDigest.Verify(Header(SignedRequestHeaders.ContentDigest), body);
	}

	[Fact]
	public async Task SignRequestAsync_emits_the_three_headers() {
		var request = await NewRequest().SignRequestAsync(KeyId, Secret);

		request.Headers.Contains(SignedRequestHeaders.ContentDigest).Should().BeTrue();
		request.Headers.Contains(SignedRequestHeaders.SignatureInput).Should().BeTrue();
		request.Headers.Contains(SignedRequestHeaders.Signature).Should().BeTrue();
	}

	[Fact]
	public async Task A_signed_request_verifies_with_common_primitives() {
		var request = await NewRequest().SignRequestAsync(KeyId, Secret);

		VerifyWithCommonPrimitives(request, Secret).Should().BeTrue();
	}

	[Fact]
	public async Task Signing_with_credentials_verifies() {
		var request = await NewRequest("https://api.example.com/orders", body: null).SignRequestAsync(new SigningCredentials(KeyId, Secret));

		VerifyWithCommonPrimitives(request, Secret).Should().BeTrue();
	}

	[Fact]
	public async Task A_wrong_secret_does_not_verify() {
		var request = await NewRequest().SignRequestAsync(KeyId, Secret);

		VerifyWithCommonPrimitives(request, "a-different-signing-secret").Should().BeFalse();
	}

	[Fact]
	public async Task Signing_a_relative_RequestUri_throws() {
		var request = new HttpRequestMessage(HttpMethod.Get, "orders?page=1");

		var act = () => request.SignRequestAsync(KeyId, Secret);

		await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*absolute RequestUri*");
	}

	[Fact]
	public async Task Signing_with_a_secret_below_the_floor_throws() {
		var act = () => NewRequest().SignRequestAsync(KeyId, "short");

		await act.Should().ThrowAsync<ArgumentException>();
	}
}
