namespace OpenVEX;

/// <summary>
/// Checks OpenVEX documents against the OpenVEX 0.2.0 JSON schema.
/// </summary>
internal static class VexValidator
{
    private static readonly HashSet<string> IdentifierNames = new(StringComparer.Ordinal)
    {
        "purl",
        "cpe22",
        "cpe23",
    };

    private static readonly HashSet<string> HashNames = new(StringComparer.Ordinal)
    {
        "md5",
        "sha1",
        "sha-256",
        "sha-384",
        "sha-512",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
        "blake2s-256",
        "blake2b-256",
        "blake2b-512",
    };

    /// <summary>
    /// Checks an OpenVEX document.
    /// </summary>
    /// <param name="document">The document to validate.</param>
    /// <returns>All validation errors found in the document.</returns>
    internal static VexValidationResult Validate(Vex document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var context = new ValidationContext();
        ValidateDocument(document, context);
        return new VexValidationResult(context.Errors);
    }

    private static void ValidateDocument(Vex document, ValidationContext context)
    {
        ValidateRequiredAbsoluteUri(document.Context, "$['@context']", context);
        ValidateRequiredAbsoluteUri(document.Id, "$['@id']", context);

        if (document.Author is null)
        {
            context.Add("$.author", "Author is required.");
        }

        if (document.Version < 1)
        {
            context.Add("$.version", "Version must be at least 1.");
        }

        var statements = context.Materialize(document.Statements);
        if (statements is null)
        {
            context.Add("$.statements", "Statements are required.");
            return;
        }

        if (statements.Length == 0)
        {
            context.Add("$.statements", "Statements must contain at least one item.");
        }

        for (var index = 0; index < statements.Length; index++)
        {
            var statement = statements[index];
            var path = $"$.statements[{index}]";

            if (statement is null)
            {
                context.Add(path, "Statement must not be null.");
                continue;
            }

            ValidateStatement(statement, path, context);
        }

        ValidateUnique(
            statements,
            "$.statements",
            context,
            (left, right) => StatementEquals(left, right, context));
    }

    private static void ValidateStatement(Statement statement, string path, ValidationContext context)
    {
        if (statement.Id is not null)
        {
            ValidateAbsoluteUri(statement.Id, $"{path}['@id']", context);
        }

        if (statement.Version is < 1)
        {
            context.Add($"{path}.version", "Statement version must be at least 1 when present.");
        }

        if (statement.Vulnerability is null)
        {
            context.Add($"{path}.vulnerability", "Vulnerability is required.");
        }
        else
        {
            ValidateVulnerability(statement.Vulnerability, $"{path}.vulnerability", context);
        }

        if (!Enum.IsDefined(statement.Status))
        {
            context.Add($"{path}.status", "Status must be a defined OpenVEX status.");
        }

        if (statement.Justification is { } justification && !Enum.IsDefined(justification))
        {
            context.Add($"{path}.justification", "Justification must be a defined OpenVEX justification.");
        }

        if (statement.Status == Status.NotAffected &&
            statement.Justification is null &&
            statement.ImpactStatement is null)
        {
            context.Add(
                path,
                "A not_affected statement must include justification or impact_statement.");
        }
        else if (statement.Status == Status.Affected && statement.ActionStatement is null)
        {
            context.Add($"{path}.action_statement", "An affected statement must include action_statement.");
        }

        var products = context.Materialize(statement.Products);
        if (products is null)
        {
            return;
        }

        for (var index = 0; index < products.Length; index++)
        {
            var product = products[index];
            var productPath = $"{path}.products[{index}]";

            if (product is null)
            {
                context.Add(productPath, "Product must not be null.");
                continue;
            }

            ValidateProduct(product, productPath, context);
        }

        ValidateUnique(
            products,
            $"{path}.products",
            context,
            (left, right) => ProductEquals(left, right, context));
    }

    private static void ValidateVulnerability(
        Vulnerability vulnerability,
        string path,
        ValidationContext context)
    {
        if (vulnerability.Id is not null)
        {
            ValidateAbsoluteUri(vulnerability.Id, $"{path}['@id']", context);
        }

        if (vulnerability.Name is null)
        {
            context.Add($"{path}.name", "Vulnerability name is required.");
        }

        var aliases = context.Materialize(vulnerability.Aliases);
        if (aliases is null)
        {
            return;
        }

        for (var index = 0; index < aliases.Length; index++)
        {
            if (aliases[index] is null)
            {
                context.Add($"{path}.aliases[{index}]", "Alias must not be null.");
            }
        }

        ValidateUnique(
            aliases,
            $"{path}.aliases",
            context,
            static (left, right) => string.Equals(left, right, StringComparison.Ordinal));
    }

    private static void ValidateProduct(Product product, string path, ValidationContext context)
    {
        ValidateComponentFields(product.Id, product.Identifiers, product.Hashes, path, context);

        var subcomponents = context.Materialize(product.Subcomponents);
        if (subcomponents is null)
        {
            return;
        }

        for (var index = 0; index < subcomponents.Length; index++)
        {
            var subcomponent = subcomponents[index];
            var subcomponentPath = $"{path}.subcomponents[{index}]";

            if (subcomponent is null)
            {
                context.Add(subcomponentPath, "Subcomponent must not be null.");
                continue;
            }

            ValidateComponent(subcomponent, subcomponentPath, context);
        }

        ValidateUnique(
            subcomponents,
            $"{path}.subcomponents",
            context,
            ComponentEquals);
    }

    private static void ValidateComponent(Component component, string path, ValidationContext context) =>
        ValidateComponentFields(component.Id, component.Identifiers, component.Hashes, path, context);

    private static void ValidateComponentFields(
        string? id,
        IDictionary<string, string>? identifiers,
        IDictionary<string, string>? hashes,
        string path,
        ValidationContext context)
    {
        if (id is not null)
        {
            ValidateAbsoluteUri(id, $"{path}['@id']", context);
        }

        if (id is null && identifiers is null)
        {
            context.Add(path, "A product or component must include @id or identifiers.");
        }

        ValidateIdentifiers(identifiers, $"{path}.identifiers", context);
        ValidateHashes(hashes, $"{path}.hashes", context);
    }

    private static void ValidateIdentifiers(
        IDictionary<string, string>? identifiers,
        string path,
        ValidationContext context)
    {
        if (identifiers is null)
        {
            return;
        }

        var hasSupportedIdentifier = false;
        foreach (var identifier in identifiers)
        {
            var identifierPath = DictionaryPath(path, identifier.Key);
            if (!IdentifierNames.Contains(identifier.Key))
            {
                context.Add(identifierPath, $"Unsupported identifier type '{identifier.Key}'.");
                continue;
            }

            hasSupportedIdentifier = true;
            if (identifier.Value is null)
            {
                context.Add(identifierPath, "Identifier value must not be null.");
            }
        }

        if (!hasSupportedIdentifier)
        {
            context.Add(path, "Identifiers must include purl, cpe22, or cpe23.");
        }
    }

    private static void ValidateHashes(
        IDictionary<string, string>? hashes,
        string path,
        ValidationContext context)
    {
        if (hashes is null)
        {
            return;
        }

        foreach (var hash in hashes)
        {
            var hashPath = DictionaryPath(path, hash.Key);
            if (!HashNames.Contains(hash.Key))
            {
                context.Add(hashPath, $"Unsupported hash algorithm '{hash.Key}'.");
            }

            if (hash.Value is null)
            {
                context.Add(hashPath, "Hash value must not be null.");
            }
        }
    }

    private static void ValidateRequiredAbsoluteUri(
        string? value,
        string path,
        ValidationContext context)
    {
        if (value is null)
        {
            context.Add(path, "Value is required.");
            return;
        }

        ValidateAbsoluteUri(value, path, context);
    }

    private static void ValidateAbsoluteUri(string value, string path, ValidationContext context)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out _) ||
            !Uri.IsWellFormedUriString(value, UriKind.Absolute))
        {
            context.Add(path, "Value must be a valid absolute URI or IRI.");
        }
    }

    private static void ValidateUnique<T>(
        IReadOnlyList<T> items,
        string path,
        ValidationContext context,
        Func<T, T, bool> equals)
        where T : class
    {
        for (var index = 0; index < items.Count; index++)
        {
            for (var previousIndex = 0; previousIndex < index; previousIndex++)
            {
                var item = items[index];
                var previous = items[previousIndex];
                var areEqual = item is null
                    ? previous is null
                    : previous is not null && equals(item, previous);

                if (!areEqual)
                {
                    continue;
                }

                context.Add(
                    $"{path}[{index}]",
                    $"Item duplicates {path}[{previousIndex}], but items must be unique.");
                break;
            }
        }
    }

    private static bool StatementEquals(
        Statement left,
        Statement right,
        ValidationContext context) =>
        string.Equals(left.Id, right.Id, StringComparison.Ordinal) &&
            left.Version == right.Version &&
            ObjectEquals(left.Vulnerability, right.Vulnerability, (x, y) => VulnerabilityEquals(x, y, context)) &&
            left.Timestamp == right.Timestamp &&
            left.LastUpdated == right.LastUpdated &&
            SequenceEquals(
                context.Materialize(left.Products),
                context.Materialize(right.Products),
                (x, y) => ProductEquals(x, y, context)) &&
            left.Status == right.Status &&
            string.Equals(left.Supplier, right.Supplier, StringComparison.Ordinal) &&
            string.Equals(left.StatusNotes, right.StatusNotes, StringComparison.Ordinal) &&
            left.Justification == right.Justification &&
            string.Equals(left.ImpactStatement, right.ImpactStatement, StringComparison.Ordinal) &&
            string.Equals(left.ActionStatement, right.ActionStatement, StringComparison.Ordinal) &&
            left.ActionStatementTimestamp == right.ActionStatementTimestamp;

    private static bool VulnerabilityEquals(
        Vulnerability left,
        Vulnerability right,
        ValidationContext context) =>
        string.Equals(left.Id, right.Id, StringComparison.Ordinal) &&
            string.Equals(left.Name, right.Name, StringComparison.Ordinal) &&
            string.Equals(left.Description, right.Description, StringComparison.Ordinal) &&
            SequenceEquals(
                context.Materialize(left.Aliases),
                context.Materialize(right.Aliases),
                static (x, y) => string.Equals(x, y, StringComparison.Ordinal));

    private static bool ProductEquals(Product left, Product right, ValidationContext context) =>
        string.Equals(left.Id, right.Id, StringComparison.Ordinal) &&
            DictionaryEquals(left.Identifiers, right.Identifiers) &&
            DictionaryEquals(left.Hashes, right.Hashes) &&
            SequenceEquals(
                context.Materialize(left.Subcomponents),
                context.Materialize(right.Subcomponents),
                ComponentEquals);

    private static bool ComponentEquals(Component left, Component right) =>
        string.Equals(left.Id, right.Id, StringComparison.Ordinal) &&
            DictionaryEquals(left.Identifiers, right.Identifiers) &&
            DictionaryEquals(left.Hashes, right.Hashes);

    private static bool DictionaryEquals(
        IDictionary<string, string>? left,
        IDictionary<string, string>? right)
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }

        if (left is null || right is null || left.Count != right.Count)
        {
            return false;
        }

        foreach (var item in left)
        {
            if (!right.Any(candidate =>
                    string.Equals(item.Key, candidate.Key, StringComparison.Ordinal) &&
                    string.Equals(item.Value, candidate.Value, StringComparison.Ordinal)))
            {
                return false;
            }
        }

        return true;
    }

    private static bool ObjectEquals<T>(T? left, T? right, Func<T, T, bool> equals)
        where T : class
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }

        return left is not null && right is not null && equals(left, right);
    }

    private static bool SequenceEquals<T>(
        IReadOnlyList<T>? left,
        IReadOnlyList<T>? right,
        Func<T, T, bool> equals)
        where T : class
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }

        if (left is null || right is null || left.Count != right.Count)
        {
            return false;
        }

        for (var index = 0; index < left.Count; index++)
        {
            var leftItem = left[index];
            var rightItem = right[index];
            var areEqual = leftItem is null
                ? rightItem is null
                : rightItem is not null && equals(leftItem, rightItem);

            if (!areEqual)
            {
                return false;
            }
        }

        return true;
    }

    private static string DictionaryPath(string path, string key) =>
        $"{path}['{key.Replace("'", "\\'", StringComparison.Ordinal)}']";

    private sealed class ValidationContext
    {
        private readonly Dictionary<object, object> materializedCollections =
            new(ReferenceEqualityComparer.Instance);

        public List<VexValidationError> Errors { get; } = [];

        public void Add(string path, string message) =>
            this.Errors.Add(new VexValidationError(path, message));

        public T[]? Materialize<T>(IEnumerable<T>? values)
        {
            if (values is null)
            {
                return null;
            }

            if (!this.materializedCollections.TryGetValue(values, out var materialized))
            {
                materialized = values.ToArray();
                this.materializedCollections.Add(values, materialized);
            }

            return (T[])materialized;
        }
    }
}
