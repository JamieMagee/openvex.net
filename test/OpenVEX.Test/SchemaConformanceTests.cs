namespace OpenVEX.Test;

using System.Text.Json;
using System.Text.Json.Nodes;
using AwesomeAssertions;
using Json.Schema;

public class SchemaConformanceTests
{
    // Pinned from openvex/spec at commit 61b5f885d0f481f48683c93345e49ef1a6e9fdff.
    private static readonly JsonSchema Schema =
        JsonSchema.FromText(TestResources.Get("openvex-0.2.0.schema.json"));

    private static readonly EvaluationOptions SchemaEvaluationOptions = new()
    {
        OutputFormat = OutputFormat.List,
        RequireFormatValidation = true,
    };

    [Fact]
    public void Should_Load_Pinned_Draft_2020_12_Schema()
    {
        using var schemaDocument = JsonDocument.Parse(TestResources.Get("openvex-0.2.0.schema.json"));
        var root = schemaDocument.RootElement;

        root.GetProperty("$schema").GetString().Should()
            .Be("https://json-schema.org/draft/2020-12/schema");
        root.GetProperty("$id").GetString().Should()
            .Be("https://github.com/openvex/spec/openvex_json_schema_0.2.0.json");
    }

    [Theory]
    [InlineData("minimal.json")]
    [InlineData("comprehensive.json")]
    public void Should_Validate_Fixtures(string resource)
    {
        using var document = JsonDocument.Parse(TestResources.Get(resource));

        var result = Schema.Evaluate(document.RootElement, SchemaEvaluationOptions);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Should_Validate_Default_Model_Serialization()
    {
        var vex = new Vex
        {
            Context = "https://openvex.dev/ns/v0.2.0",
            Id = "https://example.com/vex/my-vex-document",
            Author = "security@example.com",
            AuthorRole = "Security Team",
            Timestamp = new DateTimeOffset(2026, 9, 10, 12, 0, 0, TimeSpan.Zero),
            Version = 1,
            Statements =
            [
                new Statement
                {
                    Vulnerability = new Vulnerability { Name = "CVE-2026-0001" },
                    Products =
                    [
                        new Product { Id = "pkg:npm/my-package@1.0.0" },
                    ],
                    Status = Status.NotAffected,
                    Justification = Justification.VulnerableCodeNotPresent,
                },
            ],
        };
        var instance = JsonSerializer.SerializeToElement(vex);

        var result = Schema.Evaluate(instance, SchemaEvaluationOptions);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Should_Enforce_Representative_Schema_Constraints()
    {
        var invalidVersion = GetMinimalDocument();
        invalidVersion["version"] = 0;

        var emptyStatements = GetMinimalDocument();
        emptyStatements["statements"] = new JsonArray();

        var duplicateStatements = GetMinimalDocument();
        var statements = duplicateStatements["statements"]!.AsArray();
        statements.Add(statements[0]!.DeepClone());

        var missingJustification = GetMinimalDocument();
        missingJustification["statements"]!.AsArray()[0]!.AsObject()["status"] = "not_affected";

        var invalidIri = GetMinimalDocument();
        invalidIri["@id"] = "not an iri";

        Evaluate(invalidVersion).IsValid.Should().BeFalse();
        Evaluate(emptyStatements).IsValid.Should().BeFalse();
        Evaluate(duplicateStatements).IsValid.Should().BeFalse();
        Evaluate(missingJustification).IsValid.Should().BeFalse();
        Evaluate(invalidIri).IsValid.Should().BeFalse();
    }

    [Fact]
    public void Should_Distinguish_Uri_And_Iri_Formats()
    {
        var invalidUri = GetMinimalDocument();
        invalidUri["@context"] = "https://example.com/世界";

        var encodedUri = GetMinimalDocument();
        encodedUri["@context"] = "https://example.com/%E4%B8%96%E7%95%8C";

        var unicodeIri = GetMinimalDocument();
        unicodeIri["@id"] = "https://example.com/世界";

        Evaluate(invalidUri).IsValid.Should().BeFalse();
        Evaluate(encodedUri).IsValid.Should().BeTrue();
        Evaluate(unicodeIri).IsValid.Should().BeTrue();
    }

    private static JsonObject GetMinimalDocument() =>
        JsonNode.Parse(TestResources.Get("minimal.json"))!.AsObject();

    private static EvaluationResults Evaluate(JsonNode instance)
    {
        using var document = JsonDocument.Parse(instance.ToJsonString());
        return Schema.Evaluate(document.RootElement, SchemaEvaluationOptions);
    }
}
