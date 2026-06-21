using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): See http://newosxbook.com/src.jl?tree=&file=/xnu-3247.1.106/bsd/sys/codesign.h
  // Note(k.kretov): Updated constants: https://opensource.apple.com/source/dyld/dyld-852/dyld3/CodeSigningTypes.h.auto.html

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal enum CSSLOT : uint
  {
    // @formatter:off
    CSSLOT_CODEDIRECTORY                 = 0,
    CSSLOT_INFOSLOT                      = 1,
    CSSLOT_REQUIREMENTS                  = 2,
    CSSLOT_RESOURCEDIR                   = 3,
    CSSLOT_APPLICATION                   = 4,
    CSSLOT_ENTITLEMENTS                  = 5,
    CSSLOT_REP_SPECIFIC                  = 6,
    CSSLOT_ENTITLEMENTS_DER              = 7,
    CSSLOT_LAUNCH_CONSTRAINT_SELF        = 8,
    CSSLOT_LAUNCH_CONSTRAINT_PARENT      = 9,
    CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE = 10,
    CSSLOT_LIBRARY_CONSTRAINT            = 11,
    CSSLOT_HASHABLE_ENTRIES_MAX          = CSSLOT_LIBRARY_CONSTRAINT,

    CSSLOT_ALTERNATE_CODEDIRECTORIES     = 0x1000,
    CSSLOT_ALTERNATE_CODEDIRECTORIES1    = 0x1001,
    CSSLOT_ALTERNATE_CODEDIRECTORIES2    = 0x1002,
    CSSLOT_ALTERNATE_CODEDIRECTORIES3    = 0x1003,
    CSSLOT_ALTERNATE_CODEDIRECTORIES4    = 0x1004,
    CSSLOT_ALTERNATE_CODEDIRECTORY_MAX   = 5,
    CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX,

    CSSLOT_CMS_SIGNATURE                 = 0x10000,
    // @formatter:on
  }
}