namespace Cirreum.SignedRequest;

/// <summary>
/// Pluggable signing/verification algorithm for the SignedRequest scheme. Replaces a
/// hardcoded HMAC-SHA256 implementation with a version-keyed resolver model so new
/// algorithms (Ed25519, post-quantum) register additively without modifying framework code.
/// </summary>
/// <remarks>
/// <para>
/// The contract here is the prerequisite for future
/// RFC 9421 HTTP Message Signatures alignment work.
/// <c>Cirreum.Authentication.SignedRequest</c> ships built-in algorithms (HMAC-SHA256
/// today; additional algorithms as future patches). Apps register additional
/// implementations via DI; the resolver picks by <see cref="AlgorithmId"/>.
/// </para>
/// <para>
/// Implementations are stateless and registered as singletons. The signer side
/// (<see cref="Sign"/>) is consumed by tooling and outbound HTTP signers in
/// <c>Cirreum.Authentication.SignedRequest.Client</c>; the verifier side
/// (<see cref="Verify"/>) is consumed server-side by the scheme handler.
/// </para>
/// </remarks>
public interface ISignedRequestAlgorithm {

	/// <summary>
	/// Canonical algorithm identifier (e.g., <c>"hmac-sha256"</c>, <c>"ed25519"</c>).
	/// Carried on the wire so the verifier picks the right algorithm; case-sensitive.
	/// </summary>
	string AlgorithmId { get; }

	/// <summary>
	/// Verifies <paramref name="signature"/> against <paramref name="canonicalInput"/>
	/// using <paramref name="keyMaterial"/>. Returns <see langword="true"/> only when
	/// the signature is valid under this algorithm and key.
	/// </summary>
	/// <param name="canonicalInput">The signed-over bytes (canonicalization is the
	/// algorithm's responsibility; the input here is already canonicalized).</param>
	/// <param name="signature">The signature bytes as carried on the request.</param>
	/// <param name="keyMaterial">The verification key material — symmetric secret for
	/// HMAC algorithms, public key bytes for asymmetric algorithms.</param>
	bool Verify(ReadOnlySpan<byte> canonicalInput, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> keyMaterial);

	/// <summary>
	/// Produces a signature over <paramref name="canonicalInput"/> using
	/// <paramref name="keyMaterial"/>. Used by signer-side tooling and outbound HTTP
	/// signers; server-side scheme handlers call <see cref="Verify"/> instead.
	/// </summary>
	/// <param name="canonicalInput">The bytes to sign (canonicalization is the
	/// algorithm's responsibility; the input here is already canonicalized).</param>
	/// <param name="keyMaterial">The signing key material — symmetric secret for HMAC
	/// algorithms, private key bytes for asymmetric algorithms.</param>
	byte[] Sign(ReadOnlySpan<byte> canonicalInput, ReadOnlySpan<byte> keyMaterial);

}
