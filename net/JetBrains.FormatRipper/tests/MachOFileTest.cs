using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using JetBrains.FormatRipper.MachO;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class MachOFileTest
  {
    [Flags]
    public enum Options
    {
      HasCmsBlob = 0x1,
      HashSignedBlob = 0x2
    }

    public sealed class Section
    {
      public readonly bool IsLittleEndian;
      public readonly CPU_TYPE CpuType;
      public readonly CPU_SUBTYPE CpuSubType;
      public readonly MH_FileType MhFileType;
      public readonly Options Options;
      public readonly string? CodeDirectoryBlobHash;
      public readonly string? CmsDataHash;
      public readonly string OrderedIncludeRanges;

      internal Section(
        bool isLittleEndian,
        CPU_TYPE cpuType,
        CPU_SUBTYPE cpuSubType,
        MH_FileType mhFileType,
        Options options,
        string? codeDirectoryBlobHash,
        string? cmsDataHash,
        string orderedIncludeRanges)
      {
        IsLittleEndian = isLittleEndian;
        CpuType = cpuType;
        CpuSubType = cpuSubType;
        MhFileType = mhFileType;
        Options = options;
        CodeDirectoryBlobHash = codeDirectoryBlobHash;
        CmsDataHash = cmsDataHash;
        OrderedIncludeRanges = orderedIncludeRanges;
      }
    }

    private static object?[] MakeSource(string filename, bool? isFatLittleEndian, params Section[] sections) => new object?[] { filename, isFatLittleEndian, sections };

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    private static readonly object?[] Sources =
      {
        // @formatter:off
        MakeSource("addhoc"                               , null , new Section(true , CPU_TYPE.CPU_TYPE_ARM64  , CPU_SUBTYPE.CPU_SUBTYPE_ARM64_ALL                                 , MH_FileType.MH_EXECUTE, Options.HashSignedBlob                     , "025EB09F62E679E957E46A4AD373229F7C27C47B26B08FA40EA31A1A7B542420B914A510CE134AF352882164266E74F4", null                                                                                              , "0;0;[0:10],[18:3C8],[3E8:8],[3F8:180],[588:BB88]")),
        MakeSource("cat"                                  , false, new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL                                , MH_FileType.MH_EXECUTE, Options.HashSignedBlob | Options.HasCmsBlob, "B5E1E4A45BF997C6BDB6D1716BCAE279B62B36B1FCB07E64183BC209F5E2FD4DBE8A759ECB1FB5D44B6678E222E4E4A4", "6BC01E731786AA9C85EAB2A559C4BFEE527EE8F425A4E822BECC9BB9EF8F51F1641C5FB8AB7DB1F524139441AA43191A", "4000;0;[0:10],[18:4B8],[4D8:8],[4E8:180],[678:C118]"),
                                                                   new Section(true , CPU_TYPE.CPU_TYPE_ARM64  , CPU_SUBTYPE.CPU_SUBTYPE_ARM64_E | CPU_SUBTYPE.CPU_SUBTYPE_LIB64   , MH_FileType.MH_EXECUTE, Options.HashSignedBlob | Options.HasCmsBlob, "2E4DCB03B2CEB5FB1349DBD8432750C33E6718CED1F60D9833BCF06B76105379CCE849CCE52DD45EE32D10EEF90EB9D1", "E614F32D5B5D1DAA208BFB3D9C1931ACEE72CC3EBE0AB29F0058CA45781539C60DAFFB6AA2EE3455A235FE158721F64E", "14000;0;[0:10],[18:418],[438:8],[448:180],[5D8:80D8]")),
        MakeSource("chmod.ppc64"                          , null , new Section(false, CPU_TYPE.CPU_TYPE_POWERPC, CPU_SUBTYPE.CPU_SUBTYPE_POWERPC_ALL                               , MH_FileType.MH_EXECUTE, 0                                          , null                                                                                              , null                                                                                              , "0;C;[0:10],[18:370],[38C:4],[394:2B8],[65C:3208]")),
        MakeSource("env-wrapper.x64"                      , null , new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL | CPU_SUBTYPE.CPU_SUBTYPE_LIB64, MH_FileType.MH_EXECUTE, Options.HashSignedBlob | Options.HasCmsBlob, "99A55C919491A9B604DF28EABBAFE597A8C596C84E9CCC8FD2526107A9537983F19E08E4A3AC6A629DB1893159001159", "C2B4E1CD34B73AE1352473ADF9F88C8F37F38A0371A8100FF3D4D8358C8A8A8CB22CF16BC1B405BD3A20256E61E4E92E", "0;0;[0:10],[18:380],[3A0:8],[3B0:170],[530:1D10]")),
        MakeSource("fat.bundle"                           , false, new Section(true , CPU_TYPE.CPU_TYPE_I386   , CPU_SUBTYPE.CPU_SUBTYPE_I386_ALL                                  , MH_FileType.MH_BUNDLE , 0                                          , null                                                                                              , null                                                                                              , "1000;8;[0:10],[18:E0],[FC:4],[104:114],[228:E20]"),
                                                                   new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL                                , MH_FileType.MH_BUNDLE , 0                                          , null                                                                                              , null                                                                                              , "3000;8;[0:10],[18:160],[180:8],[190:118],[2B8:DA0]")),
        MakeSource("fat.dylib"                            , false, new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL                                , MH_FileType.MH_DYLIB  , 0                                          , null                                                                                              , null                                                                                              , "1000;0;[0:10],[18:160],[180:8],[190:140],[2E0:D70]"),
                                                                   new Section(true , CPU_TYPE.CPU_TYPE_I386   , CPU_SUBTYPE.CPU_SUBTYPE_I386_ALL                                  , MH_FileType.MH_DYLIB  , 0                                          , null                                                                                              , null                                                                                              , "3000;C;[0:10],[18:E0],[FC:4],[104:13C],[250:DF4]")),
        MakeSource("fsnotifier"                           , false, new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL                                , MH_FileType.MH_EXECUTE, 0                                          , null                                                                                              , null                                                                                              , "4000;8;[0:10],[18:4C0],[4E0:8],[4F0:240],[740:8258]"),
                                                                   new Section(true , CPU_TYPE.CPU_TYPE_ARM64  , CPU_SUBTYPE.CPU_SUBTYPE_ARM64_ALL                                 , MH_FileType.MH_EXECUTE, Options.HashSignedBlob                     , "5CDCC9053E5F2E0581DA1B5EA926EB2A4B9C389324ADDAE416A0C938DB2436DE1C87422DF8A4A71C6109B7BB4BB19745", null                                                                                              , "10000;0;[0:10],[18:468],[488:8],[498:250],[6F8:C2E8]")),
        MakeSource("JetBrains.Profiler.PdbServer"         , null , new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL | CPU_SUBTYPE.CPU_SUBTYPE_LIB64, MH_FileType.MH_EXECUTE, Options.HashSignedBlob | Options.HasCmsBlob, "D893A78E3ED66133914AB5BF1C70FBBC26DA0D008E59F84064250C417781CD8D3DA904FCB62D97002C1BED15580851EE", "86D3E5693F0528858A18CBCE2773BB0A348071D40F59459EB8ACB02086C2F2805B7D58B4D65CB65A187EA584AF6A0C2A", "0;0;[0:10],[18:600],[620:8],[630:280],[8C0:19DAE0]")),
        MakeSource("libhostfxr.dylib"                     , null , new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL                                , MH_FileType.MH_DYLIB  , Options.HashSignedBlob | Options.HasCmsBlob, "23BA89AC8310F343E691757AE45A4AA60BFDD60214E86D02F41BC2186E47F5C9FFADAE08B04724C736460AF870F4A836", "E2D2A5D0815B8EB03175AB74DB0984C17BC7BBB51416DA9BD055099AB1BFA4411F868133A56A4614518315CA5C46E40D", "0;0;[0:10],[18:608],[628:8],[638:198],[7E0:661F0]")),
        MakeSource("libMonoSupportW.x64.dylib"            , null , new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL                                , MH_FileType.MH_DYLIB  , Options.HashSignedBlob | Options.HasCmsBlob, "259BBB50C214B7CD7C8CD38B2E41916ECAB5A1A21875D719CC7CF2DFB9957D9507DCE16EAD39F17AC231CEA3A1D42F59", "A6342A89E763C7223ED91ED95FECBA8B42BD97759C87ABC5E79B2E44F5184EAE36E83F3F112ADD83A2483D4D76408D20", "0;0;[0:10],[18:4C8],[4E8:8],[4F8:1F8],[700:2BBE0]")),
        MakeSource("libSystem.Net.Security.Native.dylib"  , null , new Section(true , CPU_TYPE.CPU_TYPE_ARM64  , CPU_SUBTYPE.CPU_SUBTYPE_ARM64_ALL                                 , MH_FileType.MH_DYLIB  , Options.HashSignedBlob | Options.HasCmsBlob, "11879D3D604B604D2D7132EA9AA6E51E92E44BFE6C6675402888B5A459D7E473AD410EDA26F3E09FEDAA597CAC7BBD05", "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B", "0;0;[0:10],[18:380],[3A0:8],[3B0:1E0],[5A0:C7C0]")),
        MakeSource("x64.bundle"                           , null , new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL                                , MH_FileType.MH_BUNDLE , 0                                          , null                                                                                              , null                                                                                              , "0;8;[0:10],[18:160],[180:8],[190:118],[2B8:DA0]")),
        MakeSource("x64.dylib"                            , null , new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL                                , MH_FileType.MH_DYLIB  , 0                                          , null                                                                                              , null                                                                                              , "0;0;[0:10],[18:160],[180:8],[190:140],[2E0:D70]")),
        MakeSource("x86.bundle"                           , null , new Section(true , CPU_TYPE.CPU_TYPE_I386   , CPU_SUBTYPE.CPU_SUBTYPE_I386_ALL                                  , MH_FileType.MH_BUNDLE , 0                                          , null                                                                                              , null                                                                                              , "0;8;[0:10],[18:E0],[FC:4],[104:114],[228:E20]")),
        MakeSource("x86.dylib"                            , null , new Section(true , CPU_TYPE.CPU_TYPE_I386   , CPU_SUBTYPE.CPU_SUBTYPE_I386_ALL                                  , MH_FileType.MH_DYLIB  , 0                                          , null                                                                                              , null                                                                                              , "0;C;[0:10],[18:E0],[FC:4],[104:13C],[250:DF4]")),
        MakeSource("libclang_rt.asan_iossim_dynamic.dylib", false, new Section(true , CPU_TYPE.CPU_TYPE_I386   , CPU_SUBTYPE.CPU_SUBTYPE_I386_ALL                                  , MH_FileType.MH_DYLIB  , Options.HashSignedBlob | Options.HasCmsBlob, "1771EDC81D62DB2B2CE6EF1BAE1816D482C103BA23D34DC347E3EFE5953A113A6665B893370E7CFCE487A5E3C841010B", "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B", "4000;0;[0:10],[18:48C],[4A8:4],[4B0:200],[6C0:E0780]"),
                                                                   new Section(true , CPU_TYPE.CPU_TYPE_X86_64 , CPU_SUBTYPE.CPU_SUBTYPE_X86_64_ALL                                , MH_FileType.MH_DYLIB  , Options.HashSignedBlob | Options.HasCmsBlob, "9DB34454E4A80EF9849C850249759DE7BA46ADFF9FCEC765A985BF74363104EA59166CC58208FE32F5EB7BC074A7D430", "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B", "F0000;0;[0:10],[18:5B8],[5D8:8],[5E8:208],[800:EEFF0]"),
                                                                   new Section(true , CPU_TYPE.CPU_TYPE_ARM64  , CPU_SUBTYPE.CPU_SUBTYPE_ARM64_ALL                                 , MH_FileType.MH_DYLIB  , Options.HashSignedBlob | Options.HasCmsBlob, "DEE34BB522EE25E88D8CE98D0174BC985F9CEBB83A4DA8C09C8164D2E311FB0AE02BC65A9B58E287468E027971F916EB", "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B", "1E8000;0;[0:10],[18:5B8],[5D8:8],[5E8:220],[818:E9088]")),
        MakeSource("libclang_rt.asan_ios_dynamic.dylib"   , false, new Section(true , CPU_TYPE.CPU_TYPE_ARM    , CPU_SUBTYPE.CPU_SUBTYPE_ARM_V7                                    , MH_FileType.MH_DYLIB  , Options.HashSignedBlob | Options.HasCmsBlob, "E82E90917F5C554C12E2EB3D7E39C5522FB233BC3D4EA37508E5F200C4000F0FAE10828CE0E81F202F6E85C1910A63CF", "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B", "4000;0;[0:10],[18:4D0],[4EC:4],[4F4:210],[714:BDB3C]"),
                                                                   new Section(true , CPU_TYPE.CPU_TYPE_ARM    , CPU_SUBTYPE.CPU_SUBTYPE_ARM_V7S                                   , MH_FileType.MH_DYLIB  , Options.HashSignedBlob | Options.HasCmsBlob, "6AAB394CA282E8838774C0BE0D73BEB6A16FB21561599C5CD6A9C7EAE29CE73E317ABCE032C997B825DE89D754D87B17", "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B", "CC000;0;[0:10],[18:4D0],[4EC:4],[4F4:210],[714:C1AEC]"),
                                                                   new Section(true , CPU_TYPE.CPU_TYPE_ARM    , CPU_SUBTYPE.CPU_SUBTYPE_ARM_V7K                                   , MH_FileType.MH_DYLIB  , Options.HashSignedBlob | Options.HasCmsBlob, "844CF546207CBB6F191838F50E6B98225348224BD031D008F00FFD4D371402C545E59A84E41E6946509D7CB373CA31A2", "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B", "198000;0;[0:10],[18:558],[574:4],[57C:210],[79C:C1974]"),
                                                                   new Section(true , CPU_TYPE.CPU_TYPE_ARM64  , CPU_SUBTYPE.CPU_SUBTYPE_ARM64_ALL                                 , MH_FileType.MH_DYLIB  , Options.HashSignedBlob | Options.HasCmsBlob, "EB4B9910F8BD4988D7C23B06CFD1E695889B66C9E517636C83E3E7530DE774D2F9250383581A4E84017191D43E4B910B", "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B", "264000;0;[0:10],[18:658],[678:8],[688:220],[8B8:E91D8]"))
        // @formatter:on[
      };

    [TestCaseSource(typeof(MachOFileTest), nameof(Sources))]
    [Test]
    public void Test(
      string resourceName,
      bool? expectedIsFatLittleEndian,
      Section[] expectedSections)
    {
      var file = ResourceUtil.OpenRead(ResourceCategory.MachO, resourceName, stream =>
        {
          Assert.IsTrue(MachOFile.Is(stream));
          return MachOFile.Parse(stream, MachOFile.Mode.SignatureData | MachOFile.Mode.ComputeHashInfo);
        });

      Assert.AreEqual(expectedIsFatLittleEndian, file.IsFatLittleEndian);
      Assert.AreEqual(expectedSections.Length, file.Sections.Length);
      var fileSections = file.Sections;
      for (var n = 0; n < expectedSections.Length; n++)
      {
        var expectedSection = expectedSections[n];
        var fileSection = fileSections[n];
        var indexMsg = $"Index {n}";
        Assert.AreEqual(expectedSection.IsLittleEndian, fileSection.IsLittleEndian, indexMsg);
        Assert.AreEqual(expectedSection.CpuType, fileSection.CpuType, indexMsg);
        Assert.AreEqual(expectedSection.CpuSubType, fileSection.CpuSubType, $"{indexMsg}, expected 0x{expectedSection.CpuSubType:X}, but was 0x{fileSection.CpuSubType:X}");
        Assert.AreEqual(expectedSection.MhFileType, fileSection.MhFileType, indexMsg);

        var hasSignedBlob = (expectedSection.Options & Options.HashSignedBlob) == Options.HashSignedBlob;
        var hasCmsBlob = (expectedSection.Options & Options.HasCmsBlob) == Options.HasCmsBlob;

        var signedBlob = fileSection.SignatureData.SignedBlob;
        var cmsBlob = fileSection.SignatureData.CmsBlob;

        Assert.AreEqual(hasSignedBlob, fileSection.HasSignature, indexMsg);
        Assert.AreEqual(hasSignedBlob, signedBlob != null, indexMsg);
        Assert.AreEqual(hasCmsBlob, cmsBlob != null, indexMsg);

        if (signedBlob != null)
        {
          Assert.AreEqual((byte)0xFA, signedBlob[0], indexMsg);
          Assert.AreEqual((byte)0xDE, signedBlob[1], indexMsg);
          Assert.AreEqual((byte)0x0C, signedBlob[2], indexMsg);
          Assert.AreEqual((byte)0x02, signedBlob[3], indexMsg);

          var length = checked((int)(
            (uint)signedBlob[4] << 24 |
            (uint)signedBlob[5] << 16 |
            (uint)signedBlob[6] << 8 |
            (uint)signedBlob[7] << 0));
          Assert.AreEqual(length, signedBlob.Length, indexMsg);
          
          byte[] hash;
          using (var hashAlgorithm = SHA384.Create())
            hash = hashAlgorithm.ComputeHash(signedBlob);
          Assert.AreEqual(expectedSection.CodeDirectoryBlobHash, HexUtil.ConvertToHexString(hash), indexMsg);
        }
        else
        {
          Assert.IsFalse(hasCmsBlob);
          Assert.IsNull(expectedSection.CodeDirectoryBlobHash); 
        }

        if (cmsBlob != null)
        {
          byte[] hash;
          using (var hashAlgorithm = SHA384.Create())
            hash = hashAlgorithm.ComputeHash(cmsBlob);
          Assert.AreEqual(expectedSection.CmsDataHash, HexUtil.ConvertToHexString(hash), indexMsg);
        }
        else
          Assert.IsNull(expectedSection.CmsDataHash);

        var computeHashInfo = fileSection.ComputeHashInfo;
        Assert.IsNotNull(computeHashInfo, indexMsg);
        ValidateUtil.Validate(computeHashInfo!, indexMsg);
        Assert.AreEqual(expectedSection.OrderedIncludeRanges, computeHashInfo!.ToString(), indexMsg);
      }
    }

    [TestCase("libclang_rt.cc_kext.a")]
    [TestCase("libclang_rt.soft_static.a")]
    [Test]
    public void ErrorTest(string resourceName)
    {
      ResourceUtil.OpenRead(ResourceCategory.MachO, resourceName, stream =>
        {
          Assert.IsFalse(MachOFile.Is(stream));
          Assert.That(() => MachOFile.Parse(stream), Throws.Exception);
          return false;
        });
    }

  }
}