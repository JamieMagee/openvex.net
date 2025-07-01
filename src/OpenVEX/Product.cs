namespace OpenVEX;

/// <summary>
/// A logical unit representing a piece of software.
/// The concept is intentionally broad to allow for a wide variety of use cases but generally speaking, anything that can be described in a Software Bill of Materials (SBOM) can be thought of as a product.
/// </summary>
public sealed record Product
{
    /// <summary>
    /// Optional IRI identifying the component to make it externally referenceable.
    /// </summary>
    [JsonPropertyName("@id")]
    public string? Id { get; init; }

    /// <summary>
    /// A map of software identifiers where the key is the type and the value the identifier. OpenVEX favors the use of purl but others are recognized.
    /// </summary>
    [JsonPropertyName("identifiers")]
    public IDictionary<string, string>? Identifiers { get; init; }

    /// <summary>
    /// Map of cryptographic hashes of the component. The key is the algorithm name based on the Hash Function Textual Names from IANA.
    /// </summary>
    [JsonPropertyName("hashes")]
    public IDictionary<string, string>? Hashes { get; init; }

    /// <summary>
    /// List of component structs describing the subcomponents subject of the VEX statement.
    /// </summary>
    [JsonPropertyName("subcomponents")]
    public IEnumerable<Component>? Subcomponents { get; init; }
}
