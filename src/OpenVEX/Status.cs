namespace OpenVEX;

/// <summary>
///     Status describes the exploitability status of a component with respect to a vulnerability.
/// </summary>
[JsonConverter(typeof(JsonStringEnumMemberConverter))]
public enum Status
{
    /// <summary>
    ///     StatusNotAffected means no remediation or mitigation is required.
    /// </summary>
    [JsonPropertyName("not_affected")]
    NotAffected,

    /// <summary>
    ///     StatusAffected means actions are recommended to remediate or mitigate.
    /// </summary>
    [JsonPropertyName("affected")]
    Affected,

    /// <summary>
    ///     StatusFixed means the listed products or components have been remediated (by including fixes).
    /// </summary>
    [JsonPropertyName("fixed")]
    Fixed,

    /// <summary>
    ///     StatusUnderInvestigation means the author of the VEX statement is investigating.
    /// </summary>
    [JsonPropertyName("under_investigation")]
    UnderInvestigation,
}
