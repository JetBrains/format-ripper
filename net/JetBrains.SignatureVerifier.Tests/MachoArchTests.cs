using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.SignatureVerifier.Macho;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public class MachoArchTests
  {
    [TestCase("fat.dylib", MachoConsts.MH_MAGIC_64, MachoConsts.MH_MAGIC)]
    [TestCase("x64.dylib", MachoConsts.MH_MAGIC_64)]
    [TestCase("x86.dylib", MachoConsts.MH_MAGIC)]
    [TestCase("fat.bundle", MachoConsts.MH_MAGIC, MachoConsts.MH_MAGIC_64)]
    [TestCase("x64.bundle", MachoConsts.MH_MAGIC_64)]
    [TestCase("x86.bundle", MachoConsts.MH_MAGIC)]
    [TestCase("libSystem.Net.Security.Native.dylib", MachoConsts.MH_MAGIC_64)]
    [TestCase("env-wrapper.x64", MachoConsts.MH_MAGIC_64)]
    [TestCase("libMonoSupportW.x64.dylib", MachoConsts.MH_MAGIC_64)]
    [TestCase("cat", MachoConsts.MH_MAGIC_64, MachoConsts.MH_MAGIC_64)]
    public void MachoArchExtractTest(string machoResourceName, uint expHeader1, uint? expHeader2 = null)
    {
      ReadOnlyCollection<MachoFile> result = Utils.StreamFromResource(machoResourceName,
        machoFileStream => new MachoArch(machoFileStream, ConsoleLogger.Instance).Extract());

      var expectedMachoItems = new List<uint> { expHeader1 };

      if (expHeader2.HasValue)
        expectedMachoItems.Add(expHeader2.Value);

      Assert.AreEqual(expectedMachoItems, result.Select(s => s.Magic));
    }
  }
}