namespace OpenVEX;

/// <summary>
/// Represents a VEX document and all of its contained information.
/// </summary>
public sealed record Vex
{
    /// <summary>
    /// The URL linking to the OpenVEX context definition.
    /// The URL is structured as https://openvex.dev/ns/v[version], where [version] represents the specific version number, such as v0.2.0.
    /// If the version is omitted, it defaults to v0.0.1.
    /// </summary>
    [JsonPropertyName("@context")]
    public required string Context { get; init; }

    /// <summary>
    /// The IRI identifying the VEX document.
    /// </summary>
    [JsonPropertyName("@id")]
    public required string Id { get; init; }

    /// <summary>
    /// Author is the identifier for the author of the VEX statement.
    /// This field should ideally be a machine readable identifier such as an IRI, email address, etc.
    /// author MUST be an individual or organization. author identity SHOULD be cryptographically associated with the signature of the VEX document or other exchange mechanism.
    /// </summary>
    [JsonPropertyName("author")]
    public required string Author { get; init; }

    /// <summary>
    /// Role describes the role of the document author.
    /// </summary>
    [JsonPropertyName("role")]
    public string? AuthorRole { get; init; }

    /// <summary>
    /// Timestamp defines the time at which the document was issued.
    /// </summary>
    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>
    /// Date of last modification to the document.
    /// </summary>
    [JsonPropertyName("last_updated")]
    public DateTimeOffset? LastUpdated { get; init; }

    /// <summary>
    /// Version is the document version.
    /// It must be incremented when any content within the VEX document changes, including any VEX statements included within the VEX document.
    /// </summary>
    [JsonPropertyName("version")]
    public required string Version { get; init; }

    /// <summary>
    /// Tooling expresses how the VEX document and contained VEX statements were generated.
    /// It may specify tools or automated processes used in the document or statement generation.
    /// </summary>
    [JsonPropertyName("tooling")]
    public string? Tooling { get; init; }

    /// <summary>
    /// A Statement is a declaration conveying a single <see cref="Status" /> for a single <see cref="Statement.Vulnerability" /> for one or more <see cref="Statement.Products" />s.
    /// A VEX Statement exists within a VEX Document.
    /// </summary>
    [JsonPropertyName("statements")]
    public required IEnumerable<Statement> Statements { get; init; }
}
