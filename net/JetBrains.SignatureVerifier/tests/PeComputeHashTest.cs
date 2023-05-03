using System.Security.Cryptography;
using JetBrains.FormatRipper.Pe;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  public class PeComputeHashTest
  {

    // @formatter:off
    [TestCase("IntelAudioService.exe"                             , "SHA256", "160F2FE667A9252AB5B2E01749CD40B024E749B10B49AD276345875BA073A57E")]
    [TestCase("JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe", "SHA384", "0BF275099F6C5A3F86DC2C2F7396D0BA750345ED2947F79681919AA8B8CD030454E09AB5AC8D95EC9D8695A95B1DCB0E")]
    [TestCase("JetBrains.ReSharper.TestResources.dll"             , "SHA384", "8216D6CA73079467F63E8F5822D425C48D5C415171E72F480AFFF4A1AD4BEC7750457BE0330EA28850C2CD44E72810C1")]
    [TestCase("ServiceModelRegUI.dll"                             , "SHA1"  , "D64EC6AEC642441554E7CBA0E0513E35683C87AE")]
    [TestCase("ServiceModelRegUI.dll"                             , "SHA256", "834394AC48C8AB8F6D21E64A2461BA196D28140558D36430C057E49ADF41967A")]
    [TestCase("ServiceModelRegUI_empty_sign.dll"                  , "SHA1"  , "D64EC6AEC642441554E7CBA0E0513E35683C87AE")]
    [TestCase("ServiceModelRegUI_empty_sign.dll"                  , "SHA256", "834394AC48C8AB8F6D21E64A2461BA196D28140558D36430C057E49ADF41967A")]
    [TestCase("ServiceModelRegUI_no_sign.dll"                     , "SHA1"  , "D64EC6AEC642441554E7CBA0E0513E35683C87AE")]
    [TestCase("ServiceModelRegUI_no_sign.dll"                     , "SHA256", "834394AC48C8AB8F6D21E64A2461BA196D28140558D36430C057E49ADF41967A")]
    [TestCase("ServiceModelRegUI_trimmed_sign.dll"                , "SHA1"  , "D64EC6AEC642441554E7CBA0E0513E35683C87AE")]
    [TestCase("ServiceModelRegUI_trimmed_sign.dll"                , "SHA256", "834394AC48C8AB8F6D21E64A2461BA196D28140558D36430C057E49ADF41967A")]
    [TestCase("System.Security.Principal.Windows.dll"             , "SHA512", "A4F2B45274C4CF912489BE463EB38FD817734B14232B9A9EC8B7B4C860E3200BC80C33F44F3DD7108525BF2F15F064B3B776371D266921133FA59D2990BDA22F")]
    [TestCase("shell32.dll"                                       , "SHA256", "BB79CC7089BF061ED707FFB3FFA4ADE1DDAED0396878CC92D54A0E20A3C81619")]
    [TestCase("uninst.exe"                                        , "SHA1"  , "3127E5670F8400136BD3F8C2B3713E99D74C24E9")]
    [TestCase("winrsmgr.arm.dll"                                  , "SHA384", "1768CC1A046874A40E2C2A0BB9C6F353F2944B8C1DA70CFD9BDD9ECA92217A2DFFD290775E31CF5FF5391C3D2770BEFE")]
    [TestCase("winrsmgr.arm64.dll"                                , "SHA384", "9DAB8C315D97965AB3C64BE91F88F6DE3AF06ACB1E122F897AD5515A9731A345F96AB6F5738A201CCB14850068BBD9F9")]
    [TestCase("winrsmgr.x64.dll"                                  , "SHA384", "B02129BEC77CE3FA473C93C5021313BF8790221067B3D764B54B5DF51DAD58F70E66EF8C74CEDE94A1E6980D83800469")]
    [TestCase("winrsmgr.x86.dll"                                  , "SHA384", "736F11CB4B4B51C001155DD045A0C91E3E3104821D2D5B269514358351915203E1DAF313D616B573CE063C1E1DECDDC9")]
    [TestCase("wscadminui.arm.exe"                                , "SHA256", "1922FF5BB8645F542BEEBD369210FB9E61A06EF53DE75D4B3BC5B42BFA9903B7")]
    [TestCase("wscadminui.arm64.exe"                              , "SHA256", "7D2B0F75106C52CD14C478B01A931B629A6937380DB83AC08F9CBDAEBC531EF6")]
    [TestCase("wscadminui.x64.exe"                                , "SHA256", "1EDDACFA399B9287C5002D1E94AC8D44CC2F27FAEC29C30CDE84ED2B9E478B0A")]
    [TestCase("wscadminui.x86.exe"                                , "SHA256", "8989E8F8C9E81E18BBDA215F78C3DFBBFCAD8341B265AB3AE89D749E6D9349A8")]
    // @formatter:on
    public void Test(string resourceName, string hashAlgorithmName, string expectedResult)
    {
      var result = ResourceUtil.OpenRead(ResourceCategory.Pe, resourceName, stream =>
        {
          var file = PeFile.Parse(stream, PeFile.Mode.ComputeHashInfo);
          Assert.IsNotNull(file.ComputeHashInfo);
          return HashUtil.ComputeHash(stream, file.ComputeHashInfo, new HashAlgorithmName(hashAlgorithmName));
        });
      Assert.AreEqual(expectedResult, HexUtil.ConvertToHexString(result));
    }
  }
}