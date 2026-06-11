using System;
using System.IO;
using System.Text;

namespace JetBrains.FormatRipper.Tests
{
  internal static class ResourceUtil
  {
    internal static void OpenRead(ResourceCategory category, string resourceName, Action<Stream> handler, Action<string>? onMissingResource = null)
    {
      var type = typeof(ResourceUtil);
      var fullResourceName = new StringBuilder(type.Namespace).Append(".Resources.").Append(category switch
          {
            ResourceCategory.Elf => "Elf",
            ResourceCategory.MachO => "MachO",
            ResourceCategory.Misc => "Misc",
            ResourceCategory.Msi => "Msi",
            ResourceCategory.Pe => "Pe",
            ResourceCategory.Sh => "Sh",
            ResourceCategory.Dmg => "Dmg",
            _ => new ArgumentOutOfRangeException(nameof(category), category, null)
          })
        .Append('.').Append(resourceName).ToString();
      using var stream = type.Assembly.GetManifestResourceStream(fullResourceName);
      if (stream == null)
      {
        var str = $"Missing resource stream for {fullResourceName}";
        onMissingResource?.Invoke(str);
        throw new InvalidOperationException(str);
      }
      handler(stream);
    }
  }
}