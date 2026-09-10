namespace OpenVEX.Test;

using System.Collections;
using System.Text.Json;
using AwesomeAssertions;

public class VexValidationTests
{
    [Fact]
    public void Should_Validate_Conformant_Documents()
    {
        var minimalResult = CreateValidDocument().Validate();
        var comprehensive = JsonSerializer.Deserialize<Vex>(TestResources.Get("comprehensive.json"));

        minimalResult.IsValid.Should().BeTrue();
        minimalResult.Errors.Should().BeEmpty();
        comprehensive.Should().NotBeNull();
        comprehensive.Validate().IsValid.Should().BeTrue();
    }

    [Fact]
    public void Should_Return_All_Document_Errors_In_Order()
    {
        var document = CreateValidDocument() with
        {
            Context = "not a uri",
            Id = "not an iri",
            Author = null!,
            Version = 0,
            Statements = [],
        };

        var result = document.Validate();

        result.IsValid.Should().BeFalse();
        result.Errors.Select(error => error.Path).Should().Equal(
            "$['@context']",
            "$['@id']",
            "$.author",
            "$.version",
            "$.statements");
    }

    [Fact]
    public void Should_Validate_Statement_Constraints()
    {
        var document = CreateValidDocument() with
        {
            Statements =
            [
                new Statement
                {
                    Version = 0,
                    Vulnerability = new Vulnerability { Name = "CVE-2026-0001" },
                    Status = Status.NotAffected,
                },
                new Statement
                {
                    Vulnerability = new Vulnerability { Name = "CVE-2026-0002" },
                    Status = Status.Affected,
                },
                new Statement
                {
                    Vulnerability = new Vulnerability { Name = null! },
                    Status = (Status)99,
                    Justification = (Justification)99,
                },
            ],
        };

        var result = document.Validate();

        result.Errors.Select(error => error.Path).Should().Contain(
            [
                "$.statements[0].version",
                "$.statements[0]",
                "$.statements[1].action_statement",
                "$.statements[2].vulnerability.name",
                "$.statements[2].status",
                "$.statements[2].justification",
            ]);
    }

    [Fact]
    public void Should_Validate_Component_Identifiers_And_Hashes()
    {
        var document = CreateValidDocument() with
        {
            Statements =
            [
                new Statement
                {
                    Vulnerability = new Vulnerability { Name = "CVE-2026-0001" },
                    Products =
                    [
                        new Product
                        {
                            Identifiers = new Dictionary<string, string>
                            {
                                ["npm"] = "example",
                                ["purl"] = null!,
                            },
                            Hashes = new Dictionary<string, string>
                            {
                                ["sha256"] = "abc",
                                ["sha-256"] = null!,
                            },
                            Subcomponents = [new Component()],
                        },
                        new Product
                        {
                            Hashes = new Dictionary<string, string>
                            {
                                ["sha-256"] = "abc",
                            },
                        },
                        new Product
                        {
                            Identifiers = new Dictionary<string, string>(),
                        },
                    ],
                    Status = Status.Fixed,
                },
            ],
        };

        var result = document.Validate();
        var paths = result.Errors.Select(error => error.Path);

        paths.Should().Contain(
            [
                "$.statements[0].products[0].identifiers['npm']",
                "$.statements[0].products[0].identifiers['purl']",
                "$.statements[0].products[0].hashes['sha256']",
                "$.statements[0].products[0].hashes['sha-256']",
                "$.statements[0].products[0].subcomponents[0]",
                "$.statements[0].products[1]",
                "$.statements[0].products[2].identifiers",
            ]);
    }

    [Fact]
    public void Should_Validate_Uri_And_Iri_Formats()
    {
        var document = CreateValidDocument() with
        {
            Statements =
            [
                new Statement
                {
                    Id = "not an iri",
                    Vulnerability = new Vulnerability
                    {
                        Id = "not an iri",
                        Name = "CVE-2026-0001",
                    },
                    Products =
                    [
                        new Product
                        {
                            Id = "not an iri",
                            Subcomponents =
                            [
                                new Component { Id = "not an iri" },
                            ],
                        },
                    ],
                    Status = Status.Fixed,
                },
            ],
        };

        var result = document.Validate();

        result.Errors.Select(error => error.Path).Should().Contain(
            [
                "$.statements[0]['@id']",
                "$.statements[0].vulnerability['@id']",
                "$.statements[0].products[0]['@id']",
                "$.statements[0].products[0].subcomponents[0]['@id']",
            ]);
    }

    [Fact]
    public void Should_Validate_Null_Nested_Values()
    {
        var document = CreateValidDocument() with
        {
            Statements =
            [
                new Statement
                {
                    Vulnerability = null!,
                    Products = [null!],
                    Status = Status.Fixed,
                },
                null!,
            ],
        };

        var result = document.Validate();

        result.Errors.Select(error => error.Path).Should().Contain(
            [
                "$.statements[0].vulnerability",
                "$.statements[0].products[0]",
                "$.statements[1]",
            ]);
    }

    [Fact]
    public void Should_Validate_Structural_Uniqueness()
    {
        var component = new Component { Id = "pkg:npm/component@1.0.0" };
        var product = new Product
        {
            Id = "pkg:npm/product@1.0.0",
            Identifiers = new Dictionary<string, string>
            {
                ["purl"] = "pkg:npm/product@1.0.0",
                ["cpe22"] = "cpe:/a:example:product:1.0.0",
            },
            Subcomponents =
            [
                component,
                component with { },
            ],
        };
        var duplicateProduct = product with
        {
            Identifiers = new Dictionary<string, string>
            {
                ["cpe22"] = "cpe:/a:example:product:1.0.0",
                ["purl"] = "pkg:npm/product@1.0.0",
            },
        };
        var statement = new Statement
        {
            Vulnerability = new Vulnerability
            {
                Name = "CVE-2026-0001",
                Aliases = ["ALIAS-1", "ALIAS-1"],
            },
            Products =
            [
                product,
                duplicateProduct,
            ],
            Status = Status.Fixed,
        };
        var document = CreateValidDocument() with
        {
            Statements =
            [
                statement,
                statement with { },
            ],
        };

        var result = document.Validate();
        var paths = result.Errors.Select(error => error.Path);

        paths.Should().Contain(
            [
                "$.statements[0].vulnerability.aliases[1]",
                "$.statements[0].products[0].subcomponents[1]",
                "$.statements[0].products[1]",
                "$.statements[1]",
            ]);
    }

    [Fact]
    public void Should_Enumerate_Model_Collections_Only_Once()
    {
        var component = new Component { Id = "pkg:npm/component@1.0.0" };
        var product = new Product
        {
            Id = "pkg:npm/product@1.0.0",
            Subcomponents = new SingleUseEnumerable<Component>([component]),
        };
        var products = new SingleUseEnumerable<Product>([product]);
        var vulnerability = new Vulnerability
        {
            Name = "CVE-2026-0001",
            Aliases = new SingleUseEnumerable<string>(["ALIAS-1"]),
        };
        var document = CreateValidDocument() with
        {
            Statements = new SingleUseEnumerable<Statement>(
            [
                new Statement
                {
                    Vulnerability = vulnerability,
                    Products = products,
                    Status = Status.Fixed,
                },
                new Statement
                {
                    Vulnerability = vulnerability,
                    Products = products,
                    Status = Status.UnderInvestigation,
                },
            ]),
        };

        var result = document.Validate();

        result.IsValid.Should().BeTrue();
    }

    private static Vex CreateValidDocument() =>
        new()
        {
            Context = "https://openvex.dev/ns/v0.2.0",
            Id = "https://example.com/vex",
            Author = "security@example.com",
            Timestamp = new DateTimeOffset(2026, 9, 10, 12, 0, 0, TimeSpan.Zero),
            Version = 1,
            Statements =
            [
                new Statement
                {
                    Vulnerability = new Vulnerability { Name = "CVE-2026-0001" },
                    Products =
                    [
                        new Product { Id = "pkg:npm/example@1.0.0" },
                    ],
                    Status = Status.Fixed,
                },
            ],
        };

    private sealed class SingleUseEnumerable<T>(IEnumerable<T> values) : IEnumerable<T>
    {
        private readonly IEnumerable<T> values = values;
        private bool enumerated;

        public IEnumerator<T> GetEnumerator()
        {
            if (this.enumerated)
            {
                throw new InvalidOperationException("The sequence was enumerated more than once.");
            }

            this.enumerated = true;
            return this.values.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() => this.GetEnumerator();
    }
}
