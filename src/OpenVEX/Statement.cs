namespace OpenVEX;

/// <summary>
///     A Statement is a declaration conveying a single <see cref="Status" /> for a single
///     <see cref="Vulnerability" /> for one or more <see cref="Products" />s. A VEX Statement exists
///     within a VEX Document.
/// </summary>
public sealed record Statement
{
    /// <summary>
    ///     Optional IRI identifying the statement to make it externally referenceable.
    /// </summary>
    [JsonPropertyName("@id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Id { get; init; }

    /// <summary>
    ///     Optional integer representing the statement's version number. Defaults to zero, required when incremented.
    /// </summary>
    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Version { get; init; }

    /// <summary>
    ///     A struct identifying the vulnerability. See the Vulnerability Data Structure section for the complete data structure reference.
    /// </summary>
    [JsonPropertyName("vulnerability")]
    public required Vulnerability Vulnerability { get; init; }

    /// <summary>
    ///     Timestamp is the time at which the information expressed in the Statement was known to be true. Cascades down from the document, see Inheritance.
    /// </summary>
    [JsonPropertyName("timestamp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? Timestamp { get; init; }

    /// <summary>
    ///     Timestamp when the statement was last updated.
    /// </summary>
    [JsonPropertyName("last_updated")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? LastUpdated { get; init; }

    /// <summary>
    ///     List of product structs that the statement applies to. See the Product Data Structure section for the full description. While a product is required to have a complete statement, this field is optional as it can cascade down from the encapsulating document, see Inheritance.
    /// </summary>
    [JsonPropertyName("products")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<Product>? Products { get; init; }

    /// <summary>
    ///     A VEX statement MUST provide the status of the vulnerabilities with respect to the products and components listed in the statement. status MUST be one of the labels defined by VEX, some of which have further options and requirements.
    /// </summary>
    [JsonPropertyName("status")]
    public required Status Status { get; init; }

    /// <summary>
    ///     Supplier of the product or subcomponent.
    /// </summary>
    [JsonPropertyName("supplier")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Supplier { get; init; }

    /// <summary>
    ///     A statement MAY convey information about how <see cref="Status" /> was determined and MAY reference other VEX information.
    /// </summary>
    [JsonPropertyName("status_notes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? StatusNotes { get; init; }

    /// <summary>
    ///     For statements conveying a <see cref="Status.NotAffected" /> status, a VEX statement MUST include either a status justification or an impact_statement informing why the product is not affected by the vulnerability. Justifications are fixed labels defined by VEX.
    /// </summary>
    [JsonPropertyName("justification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Justification? Justification { get; init; }

    /// <summary>
    ///     For statements conveying a <see cref="Status.NotAffected" /> status, a VEX statement MUST include either a status justification or an impact_statement informing why the product is not affected by the vulnerability. An impact statement is a free form text containing a description of why the vulnerability cannot be exploited. This field is not intended to be machine readable so its use is highly discouraged for automated systems.
    /// </summary>
    [JsonPropertyName("impact_statement")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ImpactStatement { get; init; }

    /// <summary>
    ///     For a statement with <see cref="Status.Affected" /> status, a VEX statement MUST include a statement that SHOULD describe actions to remediate or mitigate the vulnerability.
    /// </summary>
    [JsonPropertyName("action_statement")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ActionStatement { get; init; }

    /// <summary>
    ///     The timestamp when the action statement was issued.
    /// </summary>
    [JsonPropertyName("action_statement_timestamp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? ActionStatementTimestamp { get; init; }
}
