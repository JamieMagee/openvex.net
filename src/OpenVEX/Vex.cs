namespace OpenVEX;

/// <summary>
/// Represents a VEX document and all of its contained information.
/// </summary>
public sealed record Vex
{
    /// <summary>
    ///     The URL linking to the OpenVEX context definition. Fixed to https://openvex.dev/ns.
    /// </summary>
    [JsonPropertyName("@context")]
    public string Context { get; init; } = null!;

    /// <summary>
    ///     The IRI identifying the VEX document.
    /// </summary>
    [JsonPropertyName("@id")]
    public string Id { get; init; } = null!;

    /// <summary>
    ///     Author is the identifier for the author of the VEX statement. Ideally, a common name, may be a URI. Author can be
    ///     an individual or organization. The author identity SHOULD be cryptographically associated with the signature of the
    ///     VEX statement or document or transport.
    /// </summary>
    [JsonPropertyName("author")]
    public string Author { get; init; } = null!;

    /// <summary>
    ///     Role describes the role of the document author.
    /// </summary>
    [JsonPropertyName("role")]
    public string AuthorRole { get; init; } = null!;

    /// <summary>
    ///     Timestamp defines the time at which the document was issued.
    /// </summary>
    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>
    ///     Version is the document version. It must be incremented when any content within the VEX document changes, including
    ///     any VEX statements included within the VEX document.
    /// </summary>
    [JsonPropertyName("version")]
    public string Version { get; init; } = null!;

    /// <summary>
    ///     Tooling expresses how the VEX document and contained VEX statements were generated. It's optional. It may specify
    ///     tools or automated processes used in the document or statement generation.
    /// </summary>
    [JsonPropertyName("tooling")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Tooling { get; init; }

    /// <summary>
    ///     An optional field specifying who is providing the VEX document.
    /// </summary>
    [JsonPropertyName("supplier")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Supplier { get; init; }

    /// <summary>
    ///     A Statement is a declaration conveying a single <see cref="Status" /> for a single
    ///     <see cref="Statement.Vulnerability" /> for one or more <see cref="Statement.Products" />s. A VEX Statement exists
    ///     within a VEX Document.
    /// </summary>
    [JsonPropertyName("statements")]
    public IEnumerable<Statement> Statements { get; init; } = null!;
}
