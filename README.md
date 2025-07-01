# OpenVEX.NET

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/JamieMagee/openvex.net/build.yml?branch=main&style=for-the-badge)](https://github.com/JamieMagee/openvex.net/actions/workflows/build.yml?query=branch%3Amain)
[![OpenVEX NuGet Package Version](https://img.shields.io/nuget/v/OpenVEX?style=for-the-badge)](https://www.nuget.org/packages/OpenVEX/)

.NET types for [OpenVEX documents][1]

## What is VEX?

**Vulnerability Exploitability eXchange (VEX)** is a vulnerability document format designed to complement a Software Bill of Materials (SBOM) that informs users of a software product about the applicability of one or more vulnerability findings.

Security scanners often detect and flag components in software that have been identified as vulnerable. However, software may not actually be affected by these vulnerabilities for various reasons:
- The vulnerable component may have been patched
- The vulnerable code may not be present in the final product
- The vulnerable code path may not be executable in the specific context

VEX documents help reduce false positives by providing authoritative information about which vulnerabilities actually affect a given product.

## What is OpenVEX?

**OpenVEX** is a minimal, compliant, interoperable, and embeddable implementation of the VEX specification. It is:

- **SBOM Agnostic**: Works with any SBOM format (SPDX, CycloneDX, etc.)
- **Minimal**: Focuses on the core VEX use cases defined by CISA
- **Interoperable**: Compatible with other VEX implementations
- **Embeddable**: Can be integrated into various security toolchains

OpenVEX documents are JSON-LD files that contain vulnerability statements expressing the relationship between vulnerabilities and products.

## Installation

Add the OpenVEX package to your .NET project:

```bash
dotnet add package OpenVEX
```

## Usage

### Creating a VEX Document

```csharp
using OpenVEX;
using System.Text.Json;

var vex = new Vex
{
    Context = "https://openvex.dev/ns/v0.2.0",
    Id = "https://example.com/vex/my-vex-document",
    Author = "security@example.com",
    AuthorRole = "Security Team",
    Timestamp = DateTimeOffset.UtcNow,
    Version = "1",
    Statements = new[]
    {
        new Statement
        {
            Vulnerability = new Vulnerability { Name = "CVE-2023-12345" },
            Products = new[]
            {
                new Product { Id = "pkg:npm/my-package@1.0.0" }
            },
            Status = Status.NotAffected,
            Justification = Justification.VulnerableCodeNotPresent,
            StatusNotes = "This vulnerability affects a dependency that is not included in our build."
        }
    }
};

// Serialize to JSON
var json = JsonSerializer.Serialize(vex, new JsonSerializerOptions { WriteIndented = true });
Console.WriteLine(json);
```

### Reading a VEX Document

```csharp
using OpenVEX;
using System.Text.Json;

// Deserialize from JSON
var json = File.ReadAllText("my-vex-document.json");
var vex = JsonSerializer.Deserialize<Vex>(json);

// Access the data
Console.WriteLine($"VEX Document: {vex.Id}");
Console.WriteLine($"Author: {vex.Author}");
Console.WriteLine($"Statements: {vex.Statements.Count()}");

foreach (var statement in vex.Statements)
{
    Console.WriteLine($"  Vulnerability: {statement.Vulnerability.Name}");
    Console.WriteLine($"  Status: {statement.Status}");
    if (statement.Justification.HasValue)
    {
        Console.WriteLine($"  Justification: {statement.Justification}");
    }
}
```

### VEX Statement Statuses

The OpenVEX specification defines four possible statuses for vulnerabilities:

- **`NotAffected`**: The product is not affected by the vulnerability
- **`Affected`**: The product is affected by the vulnerability  
- **`Fixed`**: The vulnerability has been fixed in this version
- **`UnderInvestigation`**: It is not yet known whether the product is affected

### Working with Products

Products in VEX documents are identified using [Package URLs (PURL)](https://github.com/package-url/purl-spec):

```csharp
var statement = new Statement
{
    Vulnerability = new Vulnerability { Name = "CVE-2023-12345" },
    Products = new[]
    {
        new Product 
        { 
            Id = "pkg:npm/lodash@4.17.20",
            Identifiers = new Dictionary<string, string>
            {
                ["purl"] = "pkg:npm/lodash@4.17.20",
                ["cpe23"] = "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*"
            },
            Hashes = new Dictionary<string, string>
            {
                ["sha-256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        }
    },
    Status = Status.Fixed
};
```

## License

All packages in this repository are licensed under [the MIT license](https://opensource.org/licenses/MIT).

[1]: https://github.com/openvex/spec
