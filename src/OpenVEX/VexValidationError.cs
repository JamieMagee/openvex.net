namespace OpenVEX;

/// <summary>
/// An OpenVEX schema validation error.
/// </summary>
/// <param name="Path">The JSON path of the invalid value.</param>
/// <param name="Message">A description of the violated constraint.</param>
public sealed record VexValidationError(string Path, string Message);
