using System.Text;

namespace JetBrains.SignatureExtractor.Tests;

internal static class ResourceUtil
{
  internal static Stream OpenRead(ResourceCategory category, string resourceName)
  {
    var type = typeof(ResourceUtil);
    var fullResourceName = new StringBuilder(type.Namespace).Append(".Resources.").Append(category switch
      {
        ResourceCategory.Dmg => "Dmg",
        ResourceCategory.MachO => "MachO",
        ResourceCategory.Msi => "Msi",
        ResourceCategory.Pe => "Pe",
        _ => new ArgumentOutOfRangeException(nameof(category), category, null)
      })
      .Append('.').Append(resourceName).ToString();
    var stream = type.Assembly.GetManifestResourceStream(fullResourceName);
    if (stream == null)
      throw new InvalidOperationException($"Failed to open resource stream for {fullResourceName}");

    return stream;
  }
}