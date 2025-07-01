namespace OpenVEX.Test;

using System.Reflection;
using System.Text.Json;
using FluentAssertions;

public class VexTests
{
    private static readonly DateTimeOffset Timestamp =
        new DateTimeOffset(2023, 1, 8, 18, 2, 3, 647, TimeSpan.FromHours(-6)).AddTicks(7879);

    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };

    [Fact]
    public void Should_Deserialize()
    {
        var input = GetResource("minimal.json");

        var vex = JsonSerializer.Deserialize<Vex>(input)!;

        vex.Should().NotBeNull();
        vex.Context.Should().Be("https://openvex.dev/ns/v0.2.0");
        vex.Id.Should().Be("https://openvex.dev/docs/example/vex-9fb3463de1b57");
        vex.Author.Should().Be("Wolfi J Inkinson");
        vex.AuthorRole.Should().Be("Document Creator");
        vex.Timestamp.Should()
            .BeExactly(Timestamp);
        vex.Version.Should().Be("1");
        vex.Statements.Should().HaveCount(1);
        var statement = vex.Statements.Single();
        statement.Vulnerability.Name.Should().Be("CVE-2023-12345");
        statement.Status.Should().Be(Status.Fixed);
        statement.Products.Should().HaveCount(2);
        statement.Products!.Select(p => p.Id).Should().Contain("pkg:apk/wolfi/git@2.39.0-r1?arch=armv7").And
            .Contain("pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64");
    }

    [Fact]
    public void Should_Serialize()
    {
        var vex = new Vex
        {
            Context = "https://openvex.dev/ns/v0.2.0",
            Id = "https://openvex.dev/docs/example/vex-9fb3463de1b57",
            Author = "Wolfi J Inkinson",
            AuthorRole = "Document Creator",
            Timestamp = Timestamp,
            Version = "1",
            Statements =
            [
                new Statement
                {
                    Vulnerability = new Vulnerability { Name = "CVE-2023-12345" },
                    Products =
                    [
                        new Product { Id = "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7" },
                        new Product { Id = "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64" },
                    ],
                    Status = Status.Fixed,
                },
            ],
        };

        var json = JsonSerializer.Serialize(vex);

        json.Should().NotBeNull();
    }

    [Fact]
    public void Should_Deserialize_Comprehensive_Format()
    {
        var input = GetResource("comprehensive.json");

        var vex = JsonSerializer.Deserialize<Vex>(input)!;

        vex.Should().NotBeNull();
        vex.Context.Should().Be("https://openvex.dev/ns/v0.2.0");
        vex.Id.Should().Be("https://openvex.dev/docs/example/vex-comprehensive");
        vex.Author.Should().Be("security@example.com");
        vex.AuthorRole.Should().Be("Security Team");
        vex.Timestamp.Should().BeExactly(new DateTimeOffset(2023, 1, 16, 19, 7, 16, 853, TimeSpan.FromHours(-6)).AddTicks(4796));
        vex.LastUpdated.Should().BeExactly(new DateTimeOffset(2023, 1, 17, 10, 15, 30, 123, TimeSpan.FromHours(-6)).AddTicks(4567));
        vex.Version.Should().Be("2");
        vex.Tooling.Should().Be("VEX Generator v1.0.0");

        vex.Statements.Should().HaveCount(1);
        var statement = vex.Statements.Single();

        statement.Id.Should().Be("https://openvex.dev/statements/stmt-001");
        statement.Version.Should().Be(1);

        statement.Vulnerability.Should().NotBeNull();
        statement.Vulnerability.Id.Should().Be("https://nvd.nist.gov/vuln/detail/CVE-2021-44228");
        statement.Vulnerability.Name.Should().Be("CVE-2021-44228");
        statement.Vulnerability.Description.Should().Be("Remote code injection in Log4j");
        statement.Vulnerability.Aliases.Should().HaveCount(2);
        statement.Vulnerability.Aliases.Should().Contain("GHSA-jfh8-c2jp-5v3q").And.Contain("log4shell");

        statement.Timestamp.Should().BeExactly(new DateTimeOffset(2023, 1, 16, 19, 7, 16, 853, TimeSpan.FromHours(-6)).AddTicks(4796));
        statement.LastUpdated.Should().BeExactly(new DateTimeOffset(2023, 1, 17, 9, 30, 0, TimeSpan.FromHours(-6)));

        statement.Products.Should().HaveCount(1);
        var product = statement.Products!.Single();
        product.Id.Should().Be("pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3");
        product.Identifiers.Should().HaveCount(2);
        product.Identifiers!["purl"].Should().Be("pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3");
        product.Identifiers["cpe23"].Should().Be("cpe:2.3:a:pivotal:spring_boot:2.6.0:milestone3:*:*:*:*:*:*");
        product.Hashes.Should().HaveCount(1);
        product.Hashes!["sha-256"].Should().Be("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        product.Subcomponents.Should().HaveCount(1);
        var subcomponent = product.Subcomponents!.Single();
        subcomponent.Id.Should().Be("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        subcomponent.Identifiers.Should().HaveCount(1);
        subcomponent.Identifiers!["purl"].Should().Be("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        subcomponent.Hashes.Should().HaveCount(1);
        subcomponent.Hashes!["sha-256"].Should().Be("402fa523b96591d4450ace90e32d9f779fcfd938903e1c5bf9d3701860b8f856");

        statement.Status.Should().Be(Status.NotAffected);
        statement.Supplier.Should().Be("Pivotal Software Inc.");
        statement.StatusNotes.Should().Be("Spring Boot users are only affected if they have switched the default logging system to Log4J2.");
        statement.Justification.Should().Be(Justification.VulnerableCodeNotInExecutePath);
        statement.ImpactStatement.Should().Be("The log4j-to-slf4j and log4j-api jars included in spring-boot-starter-logging cannot be exploited on their own. Only applications using log4j-core and including user input in log messages are vulnerable.");
    }

    [Fact]
    public void Should_Serialize_Comprehensive_Format()
    {
        var vex = new Vex
        {
            Context = "https://openvex.dev/ns/v0.2.0",
            Id = "https://openvex.dev/docs/example/vex-comprehensive",
            Author = "security@example.com",
            AuthorRole = "Security Team",
            Timestamp = new DateTimeOffset(2023, 1, 16, 19, 7, 16, 853, TimeSpan.FromHours(-6)).AddTicks(4796),
            LastUpdated = new DateTimeOffset(2023, 1, 17, 10, 15, 30, 123, TimeSpan.FromHours(-6)).AddTicks(4567),
            Version = "2",
            Tooling = "VEX Generator v1.0.0",
            Statements =
            [
                new Statement
                {
                    Id = "https://openvex.dev/statements/stmt-001",
                    Version = 1,
                    Vulnerability = new Vulnerability
                    {
                        Id = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                        Name = "CVE-2021-44228",
                        Description = "Remote code injection in Log4j",
                        Aliases = ["GHSA-jfh8-c2jp-5v3q", "log4shell"],
                    },
                    Timestamp = new DateTimeOffset(2023, 1, 16, 19, 7, 16, 853, TimeSpan.FromHours(-6)).AddTicks(4796),
                    LastUpdated = new DateTimeOffset(2023, 1, 17, 9, 30, 0, TimeSpan.FromHours(-6)),
                    Products =
                    [
                        new Product
                        {
                            Id = "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
                            Identifiers = new Dictionary<string, string>
                            {
                                ["purl"] = "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
                                ["cpe23"] = "cpe:2.3:a:pivotal:spring_boot:2.6.0:milestone3:*:*:*:*:*:*",
                            },
                            Hashes = new Dictionary<string, string>
                            {
                                ["sha-256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            },
                            Subcomponents =
                            [
                                new Component
                                {
                                    Id = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                                    Identifiers = new Dictionary<string, string>
                                    {
                                        ["purl"] = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                                    },
                                    Hashes = new Dictionary<string, string>
                                    {
                                        ["sha-256"] = "402fa523b96591d4450ace90e32d9f779fcfd938903e1c5bf9d3701860b8f856",
                                    },
                                },
                            ],
                        },
                    ],
                    Status = Status.NotAffected,
                    Supplier = "Pivotal Software Inc.",
                    StatusNotes = "Spring Boot users are only affected if they have switched the default logging system to Log4J2.",
                    Justification = Justification.VulnerableCodeNotInExecutePath,
                    ImpactStatement = "The log4j-to-slf4j and log4j-api jars included in spring-boot-starter-logging cannot be exploited on their own. Only applications using log4j-core and including user input in log messages are vulnerable.",
                },
            ],
        };

        var json = JsonSerializer.Serialize(vex, SerializerOptions);

        json.Should().NotBeNull();
        json.Should().Contain("\"@context\": \"https://openvex.dev/ns/v0.2.0\"");
        json.Should().Contain("\"vulnerability\":");
        json.Should().Contain("\"name\": \"CVE-2021-44228\"");
        json.Should().Contain("\"products\":");
        json.Should().Contain("\"identifiers\":");
        json.Should().Contain("\"hashes\":");
        json.Should().Contain("\"subcomponents\":");
    }

    private static string GetResource(string resource)
    {
        var directory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        var path = Path.Combine(directory!, "Resources", resource);
        return File.ReadAllText(path);
    }
}
