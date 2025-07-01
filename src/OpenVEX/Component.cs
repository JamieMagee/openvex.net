namespace OpenVEX;

/// <summary>
/// Any components possibly included in the product where the vulnerability originates.
/// The subcomponents SHOULD also list software identifiers and they SHOULD also be listed in the product SBOM.
/// </summary>
public sealed record Component
{
    /// <summary>
    /// Optional IRI identifying the component to make it externally referenceable.
    /// </summary>
    [JsonPropertyName("@id")]
    public string? Id { get; init; }

    /// <summary>
    /// A map of software identifiers where the key is the type and the value the identifier.
    /// OpenVEX favors the use of purl but others are recognized.
    /// </summary>
    [JsonPropertyName("identifiers")]
    public IDictionary<string, string>? Identifiers { get; init; }

    /// <summary>
    /// Map of cryptographic hashes of the component.
    /// The key is the algorithm name based on the Hash Function Textual Names from IANA.
    /// </summary>
    [JsonPropertyName("hashes")]
    public IDictionary<string, string>? Hashes { get; init; }
}
