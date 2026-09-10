namespace OpenVEX;

/// <summary>
/// The result of validating an OpenVEX document.
/// </summary>
public sealed class VexValidationResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="VexValidationResult" /> class.
    /// </summary>
    /// <param name="errors">The detected validation errors.</param>
    internal VexValidationResult(IEnumerable<VexValidationError> errors) =>
        this.Errors = Array.AsReadOnly<VexValidationError>([.. errors]);

    /// <summary>
    /// Gets whether the document passed validation.
    /// </summary>
    public bool IsValid => this.Errors.Count == 0;

    /// <summary>
    /// Gets the validation errors in document order.
    /// </summary>
    public IReadOnlyList<VexValidationError> Errors { get; }
}
