using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum ELFOSABI : byte
  {
    // @formatter:off
    ELFOSABI_NONE         =   0, // UNIX System V ABI
    ELFOSABI_HPUX         =   1, // HP-UX operating system
    ELFOSABI_NETBSD       =   2, // NetBSD
    ELFOSABI_LINUX        =   3, // GNU/Linux
    ELFOSABI_HURD         =   4, // GNU/Hurd
    ELFOSABI_86OPEN       =   5, // 86Open common IA32 ABI
    ELFOSABI_SOLARIS      =   6, // Solaris
    ELFOSABI_AIX          =   7, // AIX
    ELFOSABI_IRIX         =   8, // IRIX
    ELFOSABI_FREEBSD      =   9, // FreeBSD
    ELFOSABI_TRU64        =  10, // TRU64 UNIX
    ELFOSABI_MODESTO      =  11, // Novell Modesto
    ELFOSABI_OPENBSD      =  12, // OpenBSD
    ELFOSABI_OPENVMS      =  13, // Open VMS
    ELFOSABI_NSK          =  14, // HP Non-Stop Kernel
    ELFOSABI_AROS         =  15, // Amiga Research OS
    ELFOSABI_FENIXOS      =  16, // FenixOS
    ELFOSABI_CLOUDABI     =  17, // Nuxi CloudABI
    ELFOSABI_OPENVOS      =  18, // Stratus Technologies OpenVOS
    ELFOSABI_C6000_ELFABI =  64, // Bare-metal TMS320C6000
    ELFOSABI_AMDGPU_HSA   =  64, // AMD HSA runtime
    ELFOSABI_C6000_LINUX  =  65, // Linux TMS320C6000
    ELFOSABI_ARM          =  97, // ARM
    ELFOSABI_STANDALONE   = 255  // Standalone (embedded) application
    // @formatter:on
  }
}