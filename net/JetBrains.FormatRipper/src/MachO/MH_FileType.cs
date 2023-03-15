using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum MH_FileType : uint
  {
    // @formatter:off
    MH_OBJECT      = 0x1, /* relocatable object file */
    MH_EXECUTE     = 0x2, /* demand paged executable file */
    MH_FVMLIB      = 0x3, /* fixed VM shared library file */
    MH_CORE        = 0x4, /* core file */
    MH_PRELOAD     = 0x5, /* preloaded executable file */
    MH_DYLIB       = 0x6, /* dynamically bound shared library */
    MH_DYLINKER    = 0x7, /* dynamic link editor */
    MH_BUNDLE      = 0x8, /* dynamically bound bundle file */
    MH_DYLIB_STUB  = 0x9, /* shared library stub for static */
    MH_DSYM        = 0xa, /* companion file with only debug */
    MH_KEXT_BUNDLE = 0xb, /* x86_64 kexts */
    // @formatter:on
  }
}