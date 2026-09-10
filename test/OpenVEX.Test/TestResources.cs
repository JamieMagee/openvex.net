namespace OpenVEX.Test;

using System.Reflection;

internal static class TestResources
{
    public static string Get(string resource)
    {
        var directory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        var path = Path.Combine(directory!, "Resources", resource);
        return File.ReadAllText(path);
    }
}
