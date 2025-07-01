namespace OpenVEX;

/// <summary>
/// Justification describes why a given component is not affected by a vulnerability.
/// </summary>
[JsonConverter(typeof(JsonStringEnumMemberConverter))]
public enum Justification
{
    /// <summary>
    /// ComponentNotPresent means the vulnerable component is not included in the artifact.
    /// ComponentNotPresent is a strong justification that the artifact is not affected.
    /// </summary>
    [JsonPropertyName("component_not_present")]
    ComponentNotPresent,

    /// <summary>
    /// VulnerableCodeNotPresent means the vulnerable component is included in artifact, but the vulnerable code is not present.
    /// Typically, this case occurs when source code is configured or built in a way that excluded the vulnerable code.
    /// VulnerableCodeNotPresent is a strong justification that the artifact is not affected.
    /// </summary>
    [JsonPropertyName("vulnerable_code_not_present")]
    VulnerableCodeNotPresent,

    /// <summary>
    /// VulnerableCodeNotInExecutePath means the vulnerable code (likely in subcomponents) can not be executed as it is used by the product.
    /// Typically, this case occurs when the product includes the vulnerable subcomponents and the vulnerable code but does not call or use the vulnerable code.
    /// </summary>
    [JsonPropertyName("vulnerable_code_not_in_execute_path")]
    VulnerableCodeNotInExecutePath,

    /// <summary>
    /// VulnerableCodeCannotBeControlledByAdversary means the vulnerable code cannot be controlled by an attacker to exploit the vulnerability.
    /// This justification could be difficult to prove conclusively.
    /// </summary>
    [JsonPropertyName("vulnerable_code_cannot_be_controlled_by_adversary")]
    VulnerableCodeCannotBeControlledByAdversary,

    /// <summary>
    /// InlineMitigationsAlreadyExist means the product includes built-in protections or features that prevent exploitation of the vulnerability.
    /// These built-in protections cannot be subverted by the attacker and cannot be configured or disabled by the user.
    /// These mitigations completely prevent exploitation based on known attack vectors.
    /// This justification could be difficult to prove conclusively.
    /// History is littered with examples of mitigation bypasses, typically involving minor modifications of existing exploit code.
    /// </summary>
    [JsonPropertyName("inline_mitigations_already_exist")]
    InlineMitigationsAlreadyExist,
}
