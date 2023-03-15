using System;
using JetBrains.FormatRipper.FileExplorer;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  public class FileTypeExplorerTest
  {
    // @formatter:off
    [TestCase("error0"                               , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error4"                               , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error_mach-o"                         , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error_msi"                            , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error_pe"                             , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("winrsmgr.arm.dll"                     , FileType.Pe     , FileProperties.SharedLibraryType)]
    [TestCase("winrsmgr.arm64.dll"                   , FileType.Pe     , FileProperties.SharedLibraryType)]
    [TestCase("winrsmgr.x64.dll"                     , FileType.Pe     , FileProperties.SharedLibraryType)]
    [TestCase("winrsmgr.x86.dll"                     , FileType.Pe     , FileProperties.SharedLibraryType)]
    [TestCase("wscadminui.arm.exe"                   , FileType.Pe     , FileProperties.ExecutableType)]
    [TestCase("wscadminui.arm64.exe"                 , FileType.Pe     , FileProperties.ExecutableType)]
    [TestCase("wscadminui.x64.exe"                   , FileType.Pe     , FileProperties.ExecutableType)]
    [TestCase("wscadminui.x86.exe"                   , FileType.Pe     , FileProperties.ExecutableType)]
    [TestCase("2dac4b.msi"                           , FileType.Msi    , FileProperties.Signed)]
    [TestCase("cat"                                  , FileType.MachO  , FileProperties.ExecutableType | FileProperties.MultiArch | FileProperties.Signed)]
    [TestCase("env-wrapper.x64"                      , FileType.MachO  , FileProperties.ExecutableType | FileProperties.Signed)]
    [TestCase("fat.bundle"                           , FileType.MachO  , FileProperties.BundleType | FileProperties.MultiArch)]
    [TestCase("fat.dylib"                            , FileType.MachO  , FileProperties.SharedLibraryType | FileProperties.MultiArch)]
    [TestCase("fsnotifier"                           , FileType.MachO  , FileProperties.ExecutableType | FileProperties.MultiArch)]
    [TestCase("libMonoSupportW.x64.dylib"            , FileType.MachO  , FileProperties.SharedLibraryType | FileProperties.Signed)]
    [TestCase("x64.bundle"                           , FileType.MachO  , FileProperties.BundleType)]
    [TestCase("x64.dylib"                            , FileType.MachO  , FileProperties.SharedLibraryType)]
    [TestCase("x86.bundle"                           , FileType.MachO  , FileProperties.BundleType)]
    [TestCase("x86.dylib"                            , FileType.MachO  , FileProperties.SharedLibraryType)]
    [TestCase("catsay.ppc64"                         , FileType.Elf    , FileProperties.ExecutableType)]
    [TestCase("catsay.x86"                           , FileType.Elf    , FileProperties.ExecutableType)]
    [TestCase("libpcprofile.so"                      , FileType.Elf    , FileProperties.SharedLibraryType)]
    [TestCase("libulockmgr.so.1.0.1.x64"             , FileType.Elf    , FileProperties.SharedLibraryType)]
    [TestCase("tempfile.x64"                         , FileType.Elf    , FileProperties.ExecutableType)]
    [TestCase("vl805"                                , FileType.Elf    , FileProperties.ExecutableType)]
    [TestCase("Armature.Interface.dll"               , FileType.Pe     , FileProperties.SharedLibraryType | FileProperties.Managed)]
    [TestCase("System.Security.Principal.Windows.dll", FileType.Pe     , FileProperties.SharedLibraryType | FileProperties.Managed | FileProperties.Signed)]
    [TestCase("api-ms-win-core-rtlsupport-l1-1-0.dll", FileType.Pe     , FileProperties.SharedLibraryType | FileProperties.Signed)]
    [TestCase("1.sh"                                 , FileType.Sh     , FileProperties.ExecutableType)]
    [TestCase("2.sh"                                 , FileType.Sh     , FileProperties.ExecutableType)]
    // @formatter:on
    [Test]
    public void Test(
      string filename,
      FileType expectedFileType,
      FileProperties expectedFileProperties)
    {
      var (fileType, fileProperties) = ResourceUtil.OpenRead(expectedFileType switch
        {
          FileType.Unknown => "Misc.",
          FileType.Pe => "Pe.",
          FileType.Msi => "Msi.",
          FileType.MachO => "MachO.",
          FileType.Elf => "Elf.",
          FileType.Sh => "Sh.",
          _ => throw new ArgumentOutOfRangeException(nameof(expectedFileType), expectedFileType, null)
        } + filename, FileTypeExplorer.DetectFileType);

      Assert.AreEqual(expectedFileType, fileType);
      Assert.AreEqual(expectedFileProperties, fileProperties);
    }
  }
}