namespace Cirreum.SignedRequest;

/// <summary>
/// Resolves an <see cref="ISignedRequestAlgorithm"/> by canonical algorithm identifier.
/// </summary>
/// <remarks>
/// <para>
/// The SignedRequest scheme handler reads the algorithm identifier
/// from the inbound request and asks the resolver for the matching implementation. The
/// resolver returns <see langword="null"/> for unsupported identifiers; the handler
/// rejects the request as unauthenticated when that happens.
/// </para>
/// <para>
/// Registered as a singleton in DI. The default implementation in
/// <c>Cirreum.Authentication.SignedRequest</c> walks all registered
/// <see cref="ISignedRequestAlgorithm"/> services and matches by <c>AlgorithmId</c>;
/// apps can register additional algorithms by registering additional
/// <see cref="ISignedRequestAlgorithm"/> services.
/// </para>
/// </remarks>
public interface ISignedRequestAlgorithmResolver {

	/// <summary>
	/// Resolves the algorithm registered under <paramref name="algorithmId"/>; returns
	/// <see langword="null"/> when no algorithm is registered for that identifier.
	/// </summary>
	ISignedRequestAlgorithm? Resolve(string algorithmId);

}
