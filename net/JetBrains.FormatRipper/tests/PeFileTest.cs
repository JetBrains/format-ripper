using System;
using System.Security.Cryptography;
using JetBrains.FormatRipper.Pe;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class PeFileTest
  {
    [Flags]
    public enum CodeOptions
    {
      HasCmsBlob = 0x1,
      HasMetadata = 0x2
    }

    // @formatter:off
    [TestCase("Armature.Interface.dll"                            , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 , IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasMetadata                         , null                                                                                              , "[118:8]", "0;0;[0:D8],[DC:3C],[120:14E0]")]
    [TestCase("IntelAudioService.exe"                             , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE                                                                                                                         , CodeOptions.HasCmsBlob | CodeOptions.HasMetadata, "CABDFDBE1E041E2B42301E8DC9A9B8D05E7DCE63D2A773FA971213DE105816E128D7DC73FEB979A688F00332C355577B", "[128:8]", "0;0;[0:D8],[DC:4C],[130:5DAD0]")]
    [TestCase("JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe", IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 , IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_FILE.IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_32BIT_MACHINE                                           , CodeOptions.HasCmsBlob                          , "D908B8DB1EF44291479A18163385753CEBB2E7DD256F1DDDA7C79A5E33052872792FEE7564FEFABF4D9D5D133ABF4641", "[1A8:8]", "0;0;[0:168],[16C:3C],[1B0:2279AF0]")]
    [TestCase("JetBrains.ReSharper.TestResources.dll"             , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 , IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob | CodeOptions.HasMetadata, "E84F3F5361510E25262DB51D4F3D7B762F6958553D4A84196F0DCB79618772DC5CF808FB2B253A62FB4A604BE2683019", "[118:8]", "0;0;[0:D8],[DC:3C],[120:18E0]")]
    [TestCase("ServiceModelRegUI.dll"                             , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob                          , "F25E3A0B4B930208C6524CE6F9E762BFE99C8657A0A0796144A93C003C94C8032EA50CF215043588A35BF12AB47F1DCA", "[150:8]", "0;0;[0:100],[104:4C],[158:8A8]")]
    [TestCase("ServiceModelRegUI_broken_counter_sign.dll"         , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob                          , "F84C34B0F4D2B5201D53EF92B4A437256B1D5130CA9A7C3A035DE1FEB23CC4DC5B461ED8AD82DDA15CA7DDE025DB37B3", "[150:8]", "0;0;[0:100],[104:4C],[158:8A8]")]
    [TestCase("ServiceModelRegUI_broken_hash.dll"                 , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob                          , "9A265A0C8B9955A18B4BCF6795B85F54DBDD0510BB0D9B336B33679C0C44B167154702A649B63E50198AA4507EA991BA", "[150:8]", "0;0;[0:100],[104:4C],[158:8A8]")]
    [TestCase("ServiceModelRegUI_broken_nested_sign.dll"          , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob                          , "51213207ED1B0DC09F70B9879D42D269C83068E362D7B9855F71450C49B1CAAE321DA8773FFC738DCDA2FC35C67F1B48", "[150:8]", "0;0;[0:100],[104:4C],[158:8A8]")]
    [TestCase("ServiceModelRegUI_broken_nested_sign_timestamp.dll", IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob                          , "5BFAB068C6A7298B2947EE17914FB9FC6D849C78BD442B9E9CB56E04490F5FD647A58E0DEADDE3E68FE7F1068C4BC9BE", "[150:8]", "0;0;[0:100],[104:4C],[158:8A8]")]
    [TestCase("ServiceModelRegUI_broken_sign.dll"                 , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob                          , "23D9D4D67504B25A67D897743A4CFCC6DD7B810A12E50F0D834E3FBC05BB03FF92C78EF1536F53345E9DB87B6BF18857", "[150:8]", "0;0;[0:100],[104:4C],[158:8A8]")]
    [TestCase("ServiceModelRegUI_empty_sign.dll"                  , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , 0                                               , null                                                                                              , "[150:8]", "0;0;[0:100],[104:4C],[158:8A8]")]
    [TestCase("ServiceModelRegUI_no_sign.dll"                     , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , 0                                               , null                                                                                              , "[150:8]", "0;0;[0:100],[104:4C],[158:8A8]")]
    [TestCase("ServiceModelRegUI_trimmed_sign.dll"                , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , 0                                               , null                                                                                              , "[150:8]", "0;0;[0:100],[104:4C],[158:8A8]")]
    [TestCase("System.Security.Principal.Windows.dll"             , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 , IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob | CodeOptions.HasMetadata, "81E2CE2291B5BDF0724639FA17360E4C707EF513FE15ED032A35742F910BA54CF76EA74BDE0B304A6839427DFD018A0C", "[118:8]", "0;0;[0:D8],[DC:3C],[120:16E0]")]
    [TestCase("api-ms-win-core-rtlsupport-l1-1-0.dll"             , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 , IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                                   , CodeOptions.HasCmsBlob                          , "F9EE34D26BDD204A45D80A43382C4B241E9A166F84670E6625761B44012CED0904D351676D2BB08849EE24F5592B41E5", "[150:8]", "0;0;[0:110],[114:3C],[158:6A8]")]
    [TestCase("dotnet.exe"                                        , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE                                                                                                                         , CodeOptions.HasCmsBlob                          , "5270038904B10DC31E236C424C863FA35F4B7822D826774C759E69EA05C1EA167F8CC56A2B6EE214DEF5774CB4B54569", "[1A8:8]", "0;0;[0:158],[15C:4C],[1B0:1B050]")]
    [TestCase("libcrypto-1_1-x64.dll"                             , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob                          , "4E6C2E9F3EC563CC8580BD5ABFB8AFFB160E079260E0A3C3776146FBBC34C2EA3A51C19CC5B7F60888C69FC99122C749", "[1A0:8]", "0;0;[0:150],[154:4C],[1A8:299058]")]
    [TestCase("libssl-1_1-x64.dll"                                , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob                          , "7BF27779F75B36FB25542EB7E8269CCDA7B592485457ECD236CB12323DC1EFA0B4106772C30FE43FDF5091DF1D9C761E", "[1A0:8]", "0;0;[0:150],[154:4C],[1A8:A0258]")]
    [TestCase("shell32.dll"                                       , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , CodeOptions.HasCmsBlob                          , "DE053E2A73D93500D8AAA51DD6DF217C48CBA4BBDB8D3420F4A326C601A02D761C656C48B6130FBC9715BDA8EF6A76C3", "[1A8:8]", "0;0;[0:158],[15C:4C],[1B0:735650]")]
    [TestCase("uninst.exe"                                        , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 , IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_FILE.IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE.IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE.IMAGE_FILE_32BIT_MACHINE, 0                                               , null                                                                                              , "[170:8]", "0;0;[0:130],[134:3C],[178:F2AF]")]
    [TestCase("winrsmgr.arm.dll"                                  , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_ARMNT, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE.IMAGE_FILE_DLL                                                       , 0                                               , null                                                                                              , "[150:8]", "0;0;[0:110],[114:3C],[158:2EA8]")]
    [TestCase("winrsmgr.arm64.dll"                                , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_ARM64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , 0                                               , null                                                                                              , "[150:8]", "0;0;[0:100],[104:4C],[158:6A8]")]
    [TestCase("winrsmgr.x64.dll"                                  , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                             , 0                                               , null                                                                                              , "[150:8]", "0;0;[0:100],[104:4C],[158:6A8]")]
    [TestCase("winrsmgr.x86.dll"                                  , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 , IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE.IMAGE_FILE_DLL                                                                                                   , 0                                               , null                                                                                              , "[150:8]", "0;0;[0:110],[114:3C],[158:6A8]")]
    [TestCase("wscadminui.arm.exe"                                , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_ARMNT, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE.IMAGE_FILE_32BIT_MACHINE                                                                                   , 0                                               , null                                                                                              , "[180:8]", "0;0;[0:140],[144:3C],[188:6E78]")]
    [TestCase("wscadminui.arm64.exe"                              , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_ARM64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE                                                                                                                         , 0                                               , null                                                                                              , "[188:8]", "0;0;[0:138],[13C:4C],[190:2270]")]
    [TestCase("wscadminui.x64.exe"                                , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64, IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_LARGE_ADDRESS_AWARE                                                                                                                         , 0                                               , null                                                                                              , "[190:8]", "0;0;[0:140],[144:4C],[198:2268]")]
    [TestCase("wscadminui.x86.exe"                                , IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 , IMAGE_SUBSYSTEM.IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_32BIT_MACHINE                                                                                                                               , 0                                               , null                                                                                              , "[180:8]", "0;0;[0:140],[144:3C],[188:1E78]")]
    // @formatter:on
    [Test]
    public void Test(
      string resourceName,
      IMAGE_FILE_MACHINE expectedMachine,
      IMAGE_SUBSYSTEM expectedSubsystem,
      IMAGE_FILE expectedCharacteristics,
      CodeOptions expectedOptions,
      string? expectedCmsBlobHash,
      string expectedSecurityDataDirectoryRange,
      string expectedOrderedIncludeRanges)
    {
      var file = ResourceUtil.OpenRead(ResourceCategory.Pe, resourceName, stream =>
        {
          Assert.IsTrue(PeFile.Is(stream));
          return PeFile.Parse(stream, PeFile.Mode.SignatureData | PeFile.Mode.ComputeHashInfo);
        });

      Assert.AreEqual(expectedMachine, file.Machine);
      Assert.AreEqual(expectedCharacteristics, file.Characteristics, $"Expected 0x{expectedCharacteristics:X}, but was 0x{file.Characteristics:X}");
      Assert.AreEqual(expectedSubsystem, file.Subsystem);

      var hasCmsSignature = (expectedOptions & CodeOptions.HasCmsBlob) == CodeOptions.HasCmsBlob;
      var hasMetadata = (expectedOptions & CodeOptions.HasMetadata) == CodeOptions.HasMetadata;
      var signedBlob = file.SignatureData.SignedBlob;
      var cmsBlob = file.SignatureData.CmsBlob;

      Assert.AreEqual(hasCmsSignature, file.HasSignature);
      Assert.IsNull(signedBlob);
      Assert.AreEqual(hasCmsSignature, cmsBlob != null);

      if (cmsBlob != null)
      {
        byte[] hash;
        using (var hashAlgorithm = SHA384.Create())
          hash = hashAlgorithm.ComputeHash(cmsBlob);
        Assert.AreEqual(expectedCmsBlobHash, HexUtil.ConvertToHexString(hash));
      }
      else
        Assert.IsNull(expectedCmsBlobHash);

      Assert.AreEqual(hasMetadata, file.HasMetadata);
      Assert.AreEqual(expectedSecurityDataDirectoryRange, file.SecurityDataDirectoryRange.ToString());

      var computeHashInfo = file.ComputeHashInfo;
      Assert.IsNotNull(computeHashInfo);
      ValidateUtil.Validate(computeHashInfo!);
      Assert.AreEqual(expectedOrderedIncludeRanges, computeHashInfo!.ToString());
    }
  }
}