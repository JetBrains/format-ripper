using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;
using JetBrains.FormatRipper.MachO;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed partial class MachOFileTest
  {
    [Flags]
    public enum Options
    {
      HasCmsBlob         = 0x1,
      HasSignedBlob      = 0x2,
      HasEntitlements    = 0x4,
      HasEntitlementsDer = 0x8,
    }

    public sealed class Command
    {
      public readonly string Hash;
      public readonly uint Size;
      public readonly LC Type;

      internal Command(string hash, uint size, LC type)
      {
        Hash = hash;
        Size = size;
        Type = type;
      }
    }

    public sealed class Section
    {
      public readonly MachOFile.Endian Endian;
      public readonly CPU_TYPE CpuType;
      public readonly CPU_SUBTYPE CpuSubType;
      public readonly MH_FileType MhFileType;
      public readonly MH_Flags MhFlags;
      public readonly Options Options;
      public readonly string? CodeDirectoryBlobHash;
      public readonly string? CmsDataHash;
      public readonly string? EntitlementsHash;
      public readonly string? EntitlementsDerHash;
      public readonly Command[] Commands;

      internal Section(
        MachOFile.Endian endian,
        CPU_TYPE cpuType,
        CPU_SUBTYPE cpuSubType,
        MH_FileType mhFileType,
        MH_Flags mhFlags,
        Options options,
        string? codeDirectoryBlobHash,
        string? cmsDataHash,
        string? entitlementsHash,
        string? entitlementsDerHash,
        params Command[] commands)
      {
        Endian = endian;
        CpuType = cpuType;
        CpuSubType = cpuSubType;
        MhFileType = mhFileType;
        MhFlags = mhFlags;
        Options = options;
        CodeDirectoryBlobHash = codeDirectoryBlobHash;
        CmsDataHash = cmsDataHash;
        EntitlementsHash = entitlementsHash;
        EntitlementsDerHash = entitlementsDerHash;
        Commands = commands;
      }
    }

    private static object?[] MakeSource(
      string filename,
      Section section) => new object?[]
      {
        filename,
        null,
        new[] { section }
      };

    private static object?[] MakeSource(
      string filename,
      MachOFile.Endian fatEndian,
      params Section[] sections) => new object?[]
      {
        filename,
        fatEndian,
        sections
      };

    [TestCaseSource(typeof(MachOFileTest), nameof(Sources))]
    [Test]
    public void Test(
      string resourceName,
      MachOFile.Endian? expectedFatEndian,
      Section[] expectedSections)
    {
      ResourceUtil.OpenRead(ResourceCategory.MachO, resourceName, stream =>
        {
          Assert.IsTrue(MachOFile.Is(stream));
          var file = MachOFile.Parse(stream, MachOFile.Mode.SignatureData);

          var sections = file.Sections;
          Assert.AreEqual(expectedFatEndian, file.FatEndian);
          Assert.AreEqual(expectedSections.Length, sections.Length);
          for (var n = 0; n < expectedSections.Length; n++)
          {
            var expectedSection = expectedSections[n];
            var section = sections[n];

            Assert.AreEqual(expectedSection.Endian, section.Endian);
            Assert.AreEqual(expectedSection.CpuType, section.CpuType);
            Assert.AreEqual(expectedSection.CpuSubType, section.CpuSubType);
            Assert.AreEqual(expectedSection.MhFileType, section.MhFileType);
            Assert.AreEqual(expectedSection.MhFlags, section.MhFlags);

            var expectedCommands = expectedSection.Commands;
            var commands = section.Commands;
            Assert.AreEqual(expectedCommands.Length, commands.Length);
            for (var k = 0; k < expectedCommands.Length; k++)
            {
              var expectedCommand = expectedCommands[k];
              var command = commands[k];

              Assert.AreEqual(expectedCommand.Type, command.Type);
              Assert.AreEqual(expectedCommand.Size, command.Size);

              var hash = CalculateStreamHash(() => command.CreateStream());
              Assert.AreEqual(expectedCommand.Hash, hash);
            }

            var hasSignedBlob = (expectedSection.Options & Options.HasSignedBlob) == Options.HasSignedBlob;
            var hasCmsBlob = (expectedSection.Options & Options.HasCmsBlob) == Options.HasCmsBlob;
            var hasEntitlements = (expectedSection.Options & Options.HasEntitlements) == Options.HasEntitlements;
            var hasEntitlementsDer = (expectedSection.Options & Options.HasEntitlementsDer) == Options.HasEntitlementsDer;

            var signedBlob = section.SignatureData.SignedBlob;
            var cmsBlob = section.SignatureData.CmsBlob;
            var entitlements = section.Entitlements;
            var entitlementsDer = section.EntitlementsDer;

            Assert.AreEqual(hasSignedBlob, section.HasSignature);
            Assert.AreEqual(hasSignedBlob, signedBlob != null);
            Assert.AreEqual(hasCmsBlob, cmsBlob != null);
            Assert.AreEqual(hasEntitlements, entitlements != null);
            Assert.AreEqual(hasEntitlementsDer, entitlementsDer != null);

            if (signedBlob != null)
            {
              Assert.AreEqual((byte)0xFA, signedBlob[0]);
              Assert.AreEqual((byte)0xDE, signedBlob[1]);
              Assert.AreEqual((byte)0x0C, signedBlob[2]);
              Assert.AreEqual((byte)0x02, signedBlob[3]);

              var length = checked((int)(
                (uint)signedBlob[4] << 24 |
                (uint)signedBlob[5] << 16 |
                (uint)signedBlob[6] << 8 |
                (uint)signedBlob[7] << 0));
              Assert.AreEqual(length, signedBlob.Length);

              byte[] hash;
              using (var hashAlgorithm = SHA384.Create())
                hash = hashAlgorithm.ComputeHash(signedBlob);
              Assert.AreEqual(expectedSection.CodeDirectoryBlobHash, HexUtil.ConvertToHexString(hash));
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
              Assert.AreEqual(expectedSection.CmsDataHash, HexUtil.ConvertToHexString(hash));
            }
            else
              Assert.IsNull(expectedSection.CmsDataHash);

            if (entitlements != null)
            {
              byte[] hash;
              using (var hashAlgorithm = SHA384.Create())
                hash = hashAlgorithm.ComputeHash(entitlements);

              Assert.AreEqual(expectedSection.EntitlementsHash, HexUtil.ConvertToHexString(hash));
            }
            else
              Assert.Null(expectedSection.EntitlementsHash);

            if (entitlementsDer != null)
            {
              byte[] hash;
              using (var hashAlgorithm = SHA384.Create())
                hash = hashAlgorithm.ComputeHash(entitlementsDer);

              Assert.AreEqual(expectedSection.EntitlementsDerHash, HexUtil.ConvertToHexString(hash));
            }
            else
              Assert.Null(expectedSection.EntitlementsDerHash);
          }
        });
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
        });
    }

    private static string CalculateStreamHash(Func<Stream> createStream)
    {
      using var itemStream = createStream();
      using var hashAlgorithm = SHA256.Create();
      return HexUtil.ConvertToHexString(hashAlgorithm.ComputeHash(itemStream));
    }
  }
}