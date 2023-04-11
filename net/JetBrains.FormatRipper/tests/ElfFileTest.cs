using JetBrains.FormatRipper.Elf;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class ElfFileTest
  {
    // Note(ww898): Some architectures don't have the difference in interpreters!!! See https://wiki.debian.org/ArchitectureSpecificsMemo for details.
    // @formatter:off
    [TestCase("busybox-static.nixos-aarch64"  , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_EXEC, EM.EM_AARCH64    , 0u                                                                                                    , null)]
    [TestCase("busybox-static.nixos-x86_64"   , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_EXEC, EM.EM_X86_64     , 0u                                                                                                    , null)]
    [TestCase("busybox.alpine-aarch64"        , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_AARCH64    , 0u                                                                                                    , "/lib/ld-musl-aarch64.so.1")]
    [TestCase("busybox.alpine-armhf"          , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_ARM        , EF.EF_ARM_EABI_VER5 | EF.EF_ARM_ABI_FLOAT_HARD                                                        , "/lib/ld-musl-armhf.so.1")]
    [TestCase("busybox.alpine-i386"           , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_386        , 0u                                                                                                    , "/lib/ld-musl-i386.so.1")]
    [TestCase("busybox.alpine-ppc64le"        , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_PPC64      , EF.EF_PPC64_ABI_VER2                                                                                  , "/lib/ld-musl-powerpc64le.so.1")]
    [TestCase("busybox.alpine-s390x"          , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_S390       , 0u                                                                                                    , "/lib/ld-musl-s390x.so.1")]
    [TestCase("busybox.alpine-x86_64"         , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_X86_64     , 0u                                                                                                    , "/lib/ld-musl-x86_64.so.1")]
    [TestCase("catsay.ppc64"                  , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_EXEC, EM.EM_PPC64      , EF.EF_PPC64_ABI_VER1                                                                                  , null)]
    [TestCase("catsay.x86"                    , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_EXEC, EM.EM_386        , 0u                                                                                                    , null)]
    [TestCase("coreutils.nixos-aarch64"       , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_EXEC, EM.EM_AARCH64    , 0u                                                                                                    , "/nix/store/c1nqsqwl9allxbxhqx3iqfxk363qrnzv-glibc-2.32-54/lib/ld-linux-aarch64.so.1")]
    [TestCase("coreutils.nixos-x86_64"        , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_EXEC, EM.EM_X86_64     , 0u                                                                                                    , "/nix/store/jsp3h3wpzc842j0rz61m5ly71ak6qgdn-glibc-2.32-54/lib/ld-linux-x86-64.so.2")]
    [TestCase("grep.android-i386"             , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_386        , 0u                                                                                                    , "/system/bin/linker")]
    [TestCase("grep.android-x86_64"           , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_X86_64     , 0u                                                                                                    , "/system/bin/linker64")]
    [TestCase("libpcprofile.so"               , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN,  EM.EM_ARM        , EF.EF_ARM_EABI_VER5 | EF.EF_ARM_ABI_FLOAT_HARD                                                        , null)]
    [TestCase("libulockmgr.so.1.0.1.x64"      , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN,  EM.EM_X86_64     , 0U                                                                                                    , null)]
    [TestCase("mktemp.freebsd-aarch64"        , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_FREEBSD, ET.ET_EXEC, EM.EM_AARCH64    , 0u                                                                                                    , "/libexec/ld-elf.so.1")]
    [TestCase("mktemp.freebsd-i386"           , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_FREEBSD, ET.ET_EXEC, EM.EM_386        , 0u                                                                                                    , "/libexec/ld-elf.so.1")]
    [TestCase("mktemp.freebsd-powerpc"        , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_FREEBSD, ET.ET_EXEC, EM.EM_PPC        , 0u                                                                                                    , "/libexec/ld-elf.so.1")]
    [TestCase("mktemp.freebsd-powerpc64"      , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_FREEBSD, ET.ET_EXEC, EM.EM_PPC64      , EF.EF_PPC64_ABI_VER2                                                                                  , "/libexec/ld-elf.so.1")]
    [TestCase("mktemp.freebsd-powerpc64le"    , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_FREEBSD, ET.ET_EXEC, EM.EM_PPC64      , EF.EF_PPC64_ABI_VER2                                                                                  , "/libexec/ld-elf.so.1")]
    [TestCase("mktemp.freebsd-riscv64"        , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_EXEC, EM.EM_RISCV      , EF.EF_RISCV_FLOAT_ABI_DOUBLE | EF.EF_RISCV_RVC                                                        , "/libexec/ld-elf.so.1")]
    [TestCase("mktemp.freebsd-sparc64"        , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_FREEBSD, ET.ET_EXEC, EM.EM_SPARCV9    , EF.EF_SPARCV9_RMO                                                                                     , "/libexec/ld-elf.so.1")]
    [TestCase("mktemp.freebsd-x86_64"         , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_FREEBSD, ET.ET_EXEC, EM.EM_X86_64     , 0u                                                                                                    , "/libexec/ld-elf.so.1")]
    [TestCase("mktemp.gentoo-armv4tl"         , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_ARM        , EF.EF_ARM_EABI_VER5 | EF.EF_ARM_ABI_FLOAT_SOFT                                                        , "/lib/ld-linux.so.3")]
    [TestCase("mktemp.gentoo-armv7a_hf-uclibc", ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_ARM        , EF.EF_ARM_EABI_VER5 | EF.EF_ARM_ABI_FLOAT_HARD                                                        , "/lib/ld-uClibc.so.0")]
    [TestCase("mktemp.gentoo-hppa2.0"         , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_LINUX  , ET.ET_DYN , EM.EM_PARISC     , EF.EFA_PARISC_1_1                                                                                     , "/lib/ld.so.1")]
    [TestCase("mktemp.gentoo-ia64"            , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_IA_64      , EF.EF_IA_64_ABI64                                                                                     , "/lib/ld-linux-ia64.so.2")]
    [TestCase("mktemp.gentoo-m68k"            , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_68K        , 0u                                                                                                    , "/lib/ld.so.1")]
    [TestCase("mktemp.gentoo-mipsel3-uclibc"  , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_EXEC, EM.EM_MIPS       , EF.EF_MIPS_ARCH_3 | EF.EF_MIPS_ABI_O32 | EF.EF_MIPS_32BITMODE | EF.EF_MIPS_CPIC | EF.EF_MIPS_NOREORDER, "/lib/ld-uClibc.so.0")]
    [TestCase("mktemp.gentoo-sparc"           , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_SPARC32PLUS, EF.EF_SPARC_SUN_US3 | EF.EF_SPARC_SUN_US1 | EF.EF_SPARC_32PLUS                                        , "/lib/ld-linux.so.2")]
    [TestCase("mktemp.openbsd-alpha"          , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_ALPHA      , 0u                                                                                                    , "/usr/libexec/ld.so")]
    [TestCase("mktemp.openbsd-armv7"          , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_ARM        , EF.EF_ARM_EABI_VER5 | EF.EF_ARM_ABI_FLOAT_SOFT                                                        , "/usr/libexec/ld.so")]
    [TestCase("mktemp.openbsd-hppa"           , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_HPUX   , ET.ET_DYN , EM.EM_PARISC     , EF.EFA_PARISC_1_1                                                                                     , "/usr/libexec/ld.so")]
    [TestCase("mktemp.openbsd-i386"           , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_386        , 0u                                                                                                    , "/usr/libexec/ld.so")]
    [TestCase("mktemp.openbsd-landisk"        , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_SH         , EF.EF_SH2E                                                                                            , "/usr/libexec/ld.so")]
    [TestCase("mktemp.openbsd-luna88k"        , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_EXEC, EM.EM_88K        , 0u                                                                                                    , "/usr/libexec/ld.so")]
    [TestCase("mktemp.openbsd-macppc"         , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_PPC        , 0u                                                                                                    , "/usr/libexec/ld.so")]
    [TestCase("mktemp.openbsd-octeon"         , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_MIPS       , EF.EF_MIPS_ARCH_3 | EF.EF_MIPS_CPIC | EF.EF_MIPS_PIC | EF.EF_MIPS_NOREORDER                           , "/usr/libexec/ld.so")]
    [TestCase("mktemp.openbsd-powerpc64"      , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_PPC64      , EF.EF_PPC64_ABI_VER2                                                                                  , "/usr/libexec/ld.so")]
    [TestCase("mktemp.openbsd-sparc64"        , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_SPARCV9    , EF.EF_SPARCV9_RMO                                                                                     , "/usr/libexec/ld.so")]
    [TestCase("mktemp.openbsd-x86_64"         , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_X86_64     , 0u                                                                                                    , "/usr/libexec/ld.so")]
    [TestCase("nologin.opensuse-i586"         , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_386        , 0u                                                                                                    , "/lib/ld-linux.so.2")]
    [TestCase("nologin.opensuse-ppc64le"      , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_PPC64      , EF.EF_PPC64_ABI_VER2                                                                                  , "/lib64/ld64.so.2")]
    [TestCase("nologin.opensuse-s390x"        , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2MSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_S390       , 0u                                                                                                    , "/lib/ld64.so.1")]
    [TestCase("tempfile.ubuntu-aarch64"       , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_AARCH64    , 0u                                                                                                    , "/lib/ld-linux-aarch64.so.1")]
    [TestCase("tempfile.ubuntu-armhf"         , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_ARM        , EF.EF_ARM_EABI_VER5 | EF.EF_ARM_ABI_FLOAT_HARD                                                        , "/lib/ld-linux-armhf.so.3")]
    [TestCase("tempfile.ubuntu-i386"          , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_386        , 0u                                                                                                    , "/lib/ld-linux.so.2")]
    [TestCase("tempfile.ubuntu-x86_64"        , ELFCLASS.ELFCLASS64, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_NONE   , ET.ET_DYN , EM.EM_X86_64     , 0u                                                                                                    , "/lib64/ld-linux-x86-64.so.2")]
    [TestCase("vl805"                         , ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, ELFOSABI.ELFOSABI_LINUX  , ET.ET_EXEC, EM.EM_ARM        , EF.EF_ARM_EABI_VER5 | EF.EF_ARM_ABI_FLOAT_HARD                                                        , null)]
    // @formatter:on
    [Test]
    public void Test(
      string resourceName,
      ELFCLASS expectedEiClass,
      ELFDATA expectedEiData,
      ELFOSABI expectedEiOsAbi,
      ET expectedEType,
      EM expectedEMachine,
      EF expectedEFlags,
      string? expectedInterpreter)
    {
      var file = ResourceUtil.OpenRead(ResourceCategory.Elf, resourceName, stream =>
        {
          Assert.IsTrue(ElfFile.Is(stream));
          return ElfFile.Parse(stream);
        });

      Assert.AreEqual(expectedEiClass, file.EiClass);
      Assert.AreEqual(expectedEiData, file.EiData);
      Assert.AreEqual(expectedEiOsAbi, file.EiOsAbi);
      Assert.AreEqual(expectedEType, file.EType);
      Assert.AreEqual(expectedEMachine, file.EMachine);
      Assert.AreEqual(expectedEFlags, file.EFlags, $"Expected 0x{expectedEFlags:X}, but was 0x{file.EFlags:X}");
      Assert.AreEqual(expectedInterpreter, file.Interpreter);
    }
  }
}