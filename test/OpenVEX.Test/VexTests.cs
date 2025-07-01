namespace OpenVEX.Test;

using System.Reflection;
using System.Text.Json;
using FluentAssertions;

public class VexTests
{
    private static readonly DateTimeOffset Timestamp =
        new DateTimeOffset(2023, 1, 8, 18, 2, 3, 647, TimeSpan.FromHours(-6)).AddTicks(7879);

    [Fact]
    public void Should_Deserialize()
    {
        var input = GetResource("minimal.json");

        var vex = JsonSerializer.Deserialize<Vex>(input)!;

        vex.Should().NotBeNull();
        vex.Context.Should().Be("https://openvex.dev/ns");
        vex.Id.Should().Be("https://openvex.dev/docs/example/vex-9fb3463de1b57");
        vex.Author.Should().Be("Wolfi J Inkinson");
        vex.AuthorRole.Should().Be("Document Creator");
        vex.Timestamp.Should()
            .BeExactly(Timestamp);
        vex.Version.Should().Be("1");
        vex.Statements.Should().HaveCount(1);
        var statement = vex.Statements.Single();
        statement.Vulnerability.Should().Be("CVE-2023-12345");
        statement.Status.Should().Be(Status.Fixed);
        statement.Products.Should().HaveCount(2);
        statement.Products.Should().Contain("pkg:apk/wolfi/git@2.39.0-r1?arch=armv7").And
            .Contain("pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64");
    }

    [Fact]
    public void Should_Serialize()
    {
        var vex = new Vex
        {
            Context = "https://openvex.dev/ns",
            Id = "https://openvex.dev/docs/example/vex-9fb3463de1b57",
            Author = "Wolfi J Inkinson",
            AuthorRole = "Document Creator",
            Timestamp = Timestamp,
            Version = "1",
            Statements =
            [
                new Statement
                {
                    Vulnerability = "CVE-2023-12345",
                    Products =
                    [
                        "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7",
                        "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64",
                    ],
                    Status = Status.Fixed,
                },
            ],
        };

        var json = JsonSerializer.Serialize(vex);

        json.Should().NotBeNull();
    }

    private static string GetResource(string resource)
    {
        var directory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        var path = Path.Combine(directory!, "Resources", resource);
        return File.ReadAllText(path);
    }
}
