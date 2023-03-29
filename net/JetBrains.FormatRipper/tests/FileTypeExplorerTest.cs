using JetBrains.FormatRipper.FileExplorer;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  public class FileTypeExplorerTest
  {
    // @formatter:off
    [TestCase("error0"                               , ResourceCategory.Misc   , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error4"                               , ResourceCategory.Misc   , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error_mach-o"                         , ResourceCategory.Misc   , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error_msi"                            , ResourceCategory.Misc   , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error_pe"                             , ResourceCategory.Misc   , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("error_pe"                             , ResourceCategory.Misc   , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("catsay.ppc64"                         , ResourceCategory.Elf    , FileType.Elf    , FileProperties.ExecutableType)]
    [TestCase("catsay.x86"                           , ResourceCategory.Elf    , FileType.Elf    , FileProperties.ExecutableType)]
    [TestCase("libpcprofile.so"                      , ResourceCategory.Elf    , FileType.Elf    , FileProperties.SharedLibraryType)]
    [TestCase("libulockmgr.so.1.0.1.x64"             , ResourceCategory.Elf    , FileType.Elf    , FileProperties.SharedLibraryType)]
    [TestCase("tempfile.x64"                         , ResourceCategory.Elf    , FileType.Elf    , FileProperties.ExecutableType)]
    [TestCase("vl805"                                , ResourceCategory.Elf    , FileType.Elf    , FileProperties.ExecutableType)]
    [TestCase("cat"                                  , ResourceCategory.MachO  , FileType.MachO  , FileProperties.ExecutableType | FileProperties.MultiArch | FileProperties.Signed)]
    [TestCase("env-wrapper.x64"                      , ResourceCategory.MachO  , FileType.MachO  , FileProperties.ExecutableType | FileProperties.Signed)]
    [TestCase("fat.bundle"                           , ResourceCategory.MachO  , FileType.MachO  , FileProperties.BundleType | FileProperties.MultiArch)]
    [TestCase("fat.dylib"                            , ResourceCategory.MachO  , FileType.MachO  , FileProperties.SharedLibraryType | FileProperties.MultiArch)]
    [TestCase("fsnotifier"                           , ResourceCategory.MachO  , FileType.MachO  , FileProperties.ExecutableType | FileProperties.MultiArch)]
    [TestCase("libMonoSupportW.x64.dylib"            , ResourceCategory.MachO  , FileType.MachO  , FileProperties.SharedLibraryType | FileProperties.Signed)]
    [TestCase("libclang_rt.asan_iossim_dynamic.dylib", ResourceCategory.MachO  , FileType.MachO  , FileProperties.SharedLibraryType| FileProperties.MultiArch | FileProperties.Signed)]
    [TestCase("libclang_rt.cc_kext.a"                , ResourceCategory.MachO  , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("libclang_rt.soft_static.a"            , ResourceCategory.MachO  , FileType.Unknown, FileProperties.UnknownType)]
    [TestCase("x64.bundle"                           , ResourceCategory.MachO  , FileType.MachO  , FileProperties.BundleType)]
    [TestCase("x64.dylib"                            , ResourceCategory.MachO  , FileType.MachO  , FileProperties.SharedLibraryType)]
    [TestCase("x86.bundle"                           , ResourceCategory.MachO  , FileType.MachO  , FileProperties.BundleType)]
    [TestCase("x86.dylib"                            , ResourceCategory.MachO  , FileType.MachO  , FileProperties.SharedLibraryType)]
    [TestCase("2dac4b.msi"                           , ResourceCategory.Msi    , FileType.Msi    , FileProperties.Signed)]
    [TestCase("dbg_amd64_6.11.1.404.msi"             , ResourceCategory.Msi    , FileType.Msi    , FileProperties.Signed)]
    [TestCase("Armature.Interface.dll"               , ResourceCategory.Pe     , FileType.Pe     , FileProperties.SharedLibraryType | FileProperties.Managed)]
    [TestCase("System.Security.Principal.Windows.dll", ResourceCategory.Pe     , FileType.Pe     , FileProperties.SharedLibraryType | FileProperties.Managed | FileProperties.Signed)]
    [TestCase("api-ms-win-core-rtlsupport-l1-1-0.dll", ResourceCategory.Pe     , FileType.Pe     , FileProperties.SharedLibraryType | FileProperties.Signed)]
    [TestCase("winrsmgr.arm.dll"                     , ResourceCategory.Pe     , FileType.Pe     , FileProperties.SharedLibraryType)]
    [TestCase("winrsmgr.arm64.dll"                   , ResourceCategory.Pe     , FileType.Pe     , FileProperties.SharedLibraryType)]
    [TestCase("winrsmgr.x64.dll"                     , ResourceCategory.Pe     , FileType.Pe     , FileProperties.SharedLibraryType)]
    [TestCase("winrsmgr.x86.dll"                     , ResourceCategory.Pe     , FileType.Pe     , FileProperties.SharedLibraryType)]
    [TestCase("wscadminui.arm.exe"                   , ResourceCategory.Pe     , FileType.Pe     , FileProperties.ExecutableType)]
    [TestCase("wscadminui.arm64.exe"                 , ResourceCategory.Pe     , FileType.Pe     , FileProperties.ExecutableType)]
    [TestCase("wscadminui.x64.exe"                   , ResourceCategory.Pe     , FileType.Pe     , FileProperties.ExecutableType)]
    [TestCase("wscadminui.x86.exe"                   , ResourceCategory.Pe     , FileType.Pe     , FileProperties.ExecutableType)]
    [TestCase("1.sh"                                 , ResourceCategory.Sh     , FileType.Sh     , FileProperties.ExecutableType)]
    [TestCase("2.sh"                                 , ResourceCategory.Sh     , FileType.Sh     , FileProperties.ExecutableType)]
    // @formatter:on
    [Test]
    public void Test(
      string resourceName,
      ResourceCategory category,
      FileType expectedFileType,
      FileProperties expectedFileProperties)
    {
      var (fileType, fileProperties) = ResourceUtil.OpenRead(category, resourceName, FileTypeExplorer.Detect);
      Assert.AreEqual(expectedFileType, fileType);
      Assert.AreEqual(expectedFileProperties, fileProperties);
    }
  }
}