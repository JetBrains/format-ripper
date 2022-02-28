using System;
using JetBrains.SignatureVerifier.Tests;
using JetBrains.Util;
using JetBrains.Util.FileType;
using NUnit.Framework;

namespace JetBrains.Platform.Tests.Cases.Util.FileType
{
  using FileType = JetBrains.Util.FileType.FileType;

  public class FileTypeDetectorTest
  {
    [TestCase("error0", FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error4", FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error_mach-o", FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error_msi", FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error_pe", FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("wscadminui.x64.exe", FileType.Pe, FileProperties.ExecutableType)]
    [TestCase("wscadminui.x86.exe", FileType.Pe, FileProperties.ExecutableType)]
    [TestCase("winrsmgr.x64.dll", FileType.Pe, FileProperties.SharedLibraryType)]
    [TestCase("winrsmgr.x86.dll", FileType.Pe, FileProperties.SharedLibraryType)]
    [TestCase("2dac4b.msi", FileType.Msi, FileProperties.UnknownType)]
    [TestCase("env-wrapper.x64", FileType.MachO, FileProperties.ExecutableType | FileProperties.Signed)]
    [TestCase("libMonoSupportW.x64.dylib", FileType.MachO, FileProperties.SharedLibraryType | FileProperties.Signed)]
    [TestCase("fat.dylib", FileType.MachO, FileProperties.SharedLibraryType | FileProperties.MultiArch)]
    [TestCase("x64.dylib", FileType.MachO, FileProperties.SharedLibraryType)]
    [TestCase("x86.dylib", FileType.MachO, FileProperties.SharedLibraryType)]
    [TestCase("fat.bundle", FileType.MachO, FileProperties.BundleType | FileProperties.MultiArch)]
    [TestCase("x64.bundle", FileType.MachO, FileProperties.BundleType)]
    [TestCase("x86.bundle", FileType.MachO, FileProperties.BundleType)]
    [TestCase("cat", FileType.MachO, FileProperties.ExecutableType | FileProperties.MultiArch | FileProperties.Signed)]
    [TestCase("tempfile.x64", FileType.Elf, FileProperties.ExecutableType)]
    [TestCase("libulockmgr.so.1.0.1.x64", FileType.Elf, FileProperties.SharedLibraryType)]
    [TestCase("catsay.ppc64", FileType.Elf, FileProperties.ExecutableType)]
    [TestCase("catsay.x86", FileType.Elf, FileProperties.ExecutableType)]
    [TestCase("vl805", FileType.Elf, FileProperties.ExecutableType)]
    [TestCase("libpcprofile.so", FileType.Elf, FileProperties.SharedLibraryType)]
    [TestCase("System.Security.Principal.Windows.dll", FileType.Pe, FileProperties.SharedLibraryType | FileProperties.Managed | FileProperties.Signed)]
    [TestCase("api-ms-win-core-rtlsupport-l1-1-0.dll", FileType.Pe, FileProperties.SharedLibraryType | FileProperties.Signed)]
    [TestCase("Armature.Interface.dll", FileType.Pe, FileProperties.SharedLibraryType | FileProperties.Managed)]
    [TestCase("1.sh", FileType.ShebangScript, FileProperties.ExecutableType)]
    [TestCase("2.sh", FileType.ShebangScript, FileProperties.ExecutableType)]
    public void DetectFileTypeTest(string filename, FileType type, FileProperties properties)
    {
      var (fileType, fileProperties) = Utils.StreamFromResource(filename, stream => FileTypeDetector.DetectFileType(stream));
      Assert.AreEqual(type, fileType);
      Assert.AreEqual(properties, fileProperties);
    }

    [TestCase("env-wrapper.x64", new[] { ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64 })]
    [TestCase("libMonoSupportW.x64.dylib", new[] { ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64 })]
    [TestCase("fat.dylib", new[] { ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64, ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL })]
    [TestCase("x64.dylib", new[] { ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64 })]
    [TestCase("x86.dylib", new[] { ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL })]
    [TestCase("fat.bundle", new[] { ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL, ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64 })]
    [TestCase("x64.bundle", new[] { ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64 })]
    [TestCase("x86.bundle", new[] { ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL })]
    [TestCase("cat", new[] { ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64, ProcessorArchitecture.PROCESSOR_ARCHITECTURE_ARM64 })]
    public void TryParseMachOArchitecturesTest(string filename, ProcessorArchitecture[] architectures)
    {
      var (fileProperties, fileArchitectures) = Utils.StreamFromResource(filename,
        stream =>
        {
          var fileProperties = FileTypeDetector.TryParseMachO(stream, out var fileArchitectures);
          return (fileProperties, fileArchitectures);
        });

      Assert.NotNull(fileProperties);
      Assert.AreEqual(architectures, fileArchitectures);
    }
  }
}