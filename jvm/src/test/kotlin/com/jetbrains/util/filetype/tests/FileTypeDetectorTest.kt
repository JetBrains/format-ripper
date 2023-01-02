package com.jetbrains.util.filetype.tests

import com.jetbrains.util.TestUtil.enumSetOf
import com.jetbrains.util.TestUtil.getTestByteChannel
import com.jetbrains.util.filetype.FileProperties
import com.jetbrains.util.filetype.FileType
import com.jetbrains.util.filetype.FileTypeDetector.DetectFileType
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.*
import java.util.stream.Stream

class FileTypeDetectorTest {
  @ParameterizedTest
  @MethodSource("DetectFileTypeTestProvider")
  fun DetectFileTypeTest(
    filename: String,
    expectedFileType: FileType,
    expectedFileProperties: EnumSet<FileProperties>
  ) {
    val (fileType, fileProperties) = getTestByteChannel(filename).use {
      it.DetectFileType()
    }

    Assertions.assertEquals(expectedFileType, fileType)
    Assertions.assertEquals(expectedFileProperties, fileProperties)
  }

  companion object {
    @JvmStatic
    fun DetectFileTypeTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("error0", FileType.Unknown, enumSetOf(FileProperties.UnknownType)),
        Arguments.of("error4", FileType.Unknown, enumSetOf(FileProperties.UnknownType)),
        Arguments.of("error_mach-o", FileType.Unknown, enumSetOf(FileProperties.UnknownType)),
        Arguments.of("error_msi", FileType.Unknown, enumSetOf(FileProperties.UnknownType)),
        Arguments.of("error_pe", FileType.Unknown, enumSetOf(FileProperties.UnknownType)),
        Arguments.of("wscadminui.x64.exe", FileType.Pe, enumSetOf(FileProperties.ExecutableType)),
        Arguments.of("wscadminui.x86.exe", FileType.Pe, enumSetOf(FileProperties.ExecutableType)),
        Arguments.of("winrsmgr.x64.dll", FileType.Pe, enumSetOf(FileProperties.SharedLibraryType)),
        Arguments.of("winrsmgr.x86.dll", FileType.Pe, enumSetOf(FileProperties.SharedLibraryType)),
        Arguments.of("2dac4b.msi", FileType.Msi, enumSetOf(FileProperties.UnknownType)),
        Arguments.of(
          "env-wrapper.x64",
          FileType.MachO,
          enumSetOf(FileProperties.ExecutableType, FileProperties.Signed)
        ),
        Arguments.of(
          "libMonoSupportW.x64.dylib",
          FileType.MachO,
          enumSetOf(FileProperties.SharedLibraryType, FileProperties.Signed)
        ),
        Arguments.of(
          "fat.dylib",
          FileType.MachO,
          enumSetOf(FileProperties.SharedLibraryType, FileProperties.MultiArch)
        ),
        Arguments.of("x64.dylib", FileType.MachO, enumSetOf(FileProperties.SharedLibraryType)),
        Arguments.of("x86.dylib", FileType.MachO, enumSetOf(FileProperties.SharedLibraryType)),
        Arguments.of("fat.bundle", FileType.MachO, enumSetOf(FileProperties.BundleType, FileProperties.MultiArch)),
        Arguments.of("x64.bundle", FileType.MachO, enumSetOf(FileProperties.BundleType)),
        Arguments.of("x86.bundle", FileType.MachO, enumSetOf(FileProperties.BundleType)),
        Arguments.of(
          "cat",
          FileType.MachO,
          enumSetOf(FileProperties.ExecutableType, FileProperties.MultiArch, FileProperties.Signed)
        ),
        Arguments.of(
          "fsnotifier",
          FileType.MachO,
          enumSetOf(FileProperties.ExecutableType, FileProperties.MultiArch)
        ),
        Arguments.of("tempfile.x64", FileType.Elf, enumSetOf(FileProperties.ExecutableType)),
        Arguments.of("libulockmgr.so.1.0.1.x64", FileType.Elf, enumSetOf(FileProperties.SharedLibraryType)),
        Arguments.of("catsay.ppc64", FileType.Elf, enumSetOf(FileProperties.ExecutableType)),
        Arguments.of("catsay.x86", FileType.Elf, enumSetOf(FileProperties.ExecutableType)),
        Arguments.of("vl805", FileType.Elf, enumSetOf(FileProperties.ExecutableType)),
        Arguments.of("libpcprofile.so", FileType.Elf, enumSetOf(FileProperties.SharedLibraryType)),
        Arguments.of(
          "System.Security.Principal.Windows.dll",
          FileType.Pe,
          enumSetOf(FileProperties.SharedLibraryType, FileProperties.Managed, FileProperties.Signed)
        ),
        Arguments.of(
          "api-ms-win-core-rtlsupport-l1-1-0.dll",
          FileType.Pe,
          enumSetOf(FileProperties.SharedLibraryType, FileProperties.Signed)
        ),
        Arguments.of(
          "Armature.Interface.dll",
          FileType.Pe,
          enumSetOf(FileProperties.SharedLibraryType, FileProperties.Managed)
        ),
        Arguments.of("1.sh", FileType.ShebangScript, enumSetOf(FileProperties.ExecutableType)),
        Arguments.of("2.sh", FileType.ShebangScript, enumSetOf(FileProperties.ExecutableType)),
      )
    }
  }
}