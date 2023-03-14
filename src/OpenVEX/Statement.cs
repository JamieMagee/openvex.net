namespace OpenVEX;

/// <summary>
///     A Statement is a declaration conveying a single <see cref="Status" /> for a single
///     <see cref="Vulnerability" /> for one or more <see cref="Products" />s. A VEX Statement exists
///     within a VEX Document.
/// </summary>
public sealed record Statement
{
    /// <summary>
    ///     Vulnerability SHOULD use existing and well known identifiers. For example: CVE, OSV, GHSA, a supplier's
    ///     vulnerability tracking system such as RHSA or a propietary system. It is expected that vulnerability identification
    ///     systems are external to and maintained separately from VEX. vulnerability MAY be URIs or URLs. vulnerability MAY be
    ///     arbitrary and MAY be created by the VEX statement <see cref="Vex.Author" />.
    /// </summary>
    [JsonPropertyName("vulnerability")]
    public string Vulnerability { get; init; } = null!;

    /// <summary>
    ///     Optional free-form text describing the vulnerability.
    /// </summary>
    [JsonPropertyName("vuln_description")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? VulnDescription { get; init; }

    /// <summary>
    ///     Timestamp is the time at which the information expressed in the Statement was known to be true. Cascades down from
    ///     the document.
    /// </summary>
    [JsonPropertyName("timestamp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? Timestamp { get; init; }

    /// <summary>
    ///     Product identifiers that the statement applies to. Any software identifier can be used and SHOULD be traceable to a
    ///     described item in an SBOM. The use of Package URLs (purls) is recommended. While a product identifier is required
    ///     to have a complete statement, this field is optional as it can cascade down from the encapsulating document.
    /// </summary>
    [JsonPropertyName("products")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? Products { get; init; }

    /// <summary>
    ///     Identifiers of components where the vulnerability originates. While the statement asserts about the impact on the
    ///     software product, listing subcomponents let scanners find identifiers to match their findings.
    /// </summary>
    [JsonPropertyName("subcomponents")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? Subcomponents { get; init; }

    /// <summary>
    ///     A VEX statement MUST provide the status of the vulnerabilities with respect to the products and components listed
    ///     in the statement. status MUST be one of the labels defined by VEX, some of which have further options and
    ///     requirements.
    /// </summary>
    [JsonPropertyName("status")]
    public Status Status { get; init; }

    /// <summary>
    ///     A statement MAY convey information about how <see cref="Status" /> was determined and MAY reference other VEX
    ///     information.
    /// </summary>
    [JsonPropertyName("status_notes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? StatusNotes { get; init; }

    /// <summary>
    ///     For statements conveying a <see cref="OpenVEX.Status.NotAffected" /> status, a VEX statement MUST include either a
    ///     status justification or an impact_statement informing why the product is not affected by the vulnerability.
    ///     Justifications are fixed labels defined by VEX.
    /// </summary>
    [JsonPropertyName("justification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Justification? Justification { get; init; }

    /// <summary>
    ///     For statements conveying a <see cref="OpenVEX.Status.NotAffected" /> status, a VEX statement MUST include either a
    ///     status justification or an impact_statement informing why the product is not affected by the vulnerability. An
    ///     impact statement is a free form text containing a description of why the vulnerability cannot be exploited. This
    ///     field is not intended to be machine readable so its use is highly discouraged for automated systems.
    /// </summary>
    [JsonPropertyName("impact_statement")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ImpactStatement { get; init; }

    /// <summary>
    ///     For a statement with <see cref="OpenVEX.Status.Affected" /> status, a VEX statement MUST include a statement that
    ///     SHOULD describe actions to remediate or mitigate the vulnerability.
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
