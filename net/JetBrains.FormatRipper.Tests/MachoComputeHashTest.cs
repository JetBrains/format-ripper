using JetBrains.SignatureVerifier.Macho;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests.Macho
{
  public class MachoComputeHashTest
  {
    [TestCase("addhoc", "SHA1", "B447D37982D38E0B0B275DA5E6869DCA65DBFCD7")]
    [TestCase("addhoc_resigned", "SHA1", "B447D37982D38E0B0B275DA5E6869DCA65DBFCD7")]
    [TestCase("notsigned", "SHA1", "B678215ECF1F02B5E6B2D8F8ACB8DCBC71830102")]
    [TestCase("nosigned_resigned", "SHA1", "B678215ECF1F02B5E6B2D8F8ACB8DCBC71830102")]
    [TestCase("fat.dylib", "SHA1", "30D9D3BDF6E0AED26D25218834D930BD9C429808", "F55FF4062F394CBAD57C118CA364EFDD91757CEA")]
    [TestCase("fat.dylib_signed", "SHA1", "30D9D3BDF6E0AED26D25218834D930BD9C429808", "F55FF4062F394CBAD57C118CA364EFDD91757CEA")]
    public void ComputeHashTest(string machoResourceName, string alg, params string[] expectedResult)
    {
      var machoFiles = Utils.StreamFromResource(machoResourceName,
        machoFileStream => new MachoArch(machoFileStream, ConsoleLogger.Instance).Extract());

      for (var index = 0; index < machoFiles.Count; index++)
      {
        MachoFile machoFile = machoFiles[index];
        var result = machoFile.ComputeHash(alg);
        Assert.AreEqual(expectedResult[index], Utils.ConvertToHexString(result));
      }
    }
  }
}