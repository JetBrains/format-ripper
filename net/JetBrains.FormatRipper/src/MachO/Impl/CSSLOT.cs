using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): See http://newosxbook.com/src.jl?tree=&file=/xnu-3247.1.106/bsd/sys/codesign.h
  // Note(k.kretov): Updated constants: https://opensource.apple.com/source/dyld/dyld-852/dyld3/CodeSigningTypes.h.auto.html

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal static class CSSLOT
  {
    // @formatter:off
    internal const uint CSSLOT_CODEDIRECTORY = 0;
    internal const uint CSSLOT_INFOSLOT      = 1;
    internal const uint CSSLOT_REQUIREMENTS  = 2;
    internal const uint CSSLOT_RESOURCEDIR   = 3;
    internal const uint CSSLOT_APPLICATION   = 4;
    internal const uint CSSLOT_ENTITLEMENTS  = 5;
    internal const uint CSSLOT_REP_SPECIFIC  = 6;
    internal const uint CSSLOT_ENTITLEMENTS_DER              = 7;
    internal const uint CSSLOT_LAUNCH_CONSTRAINT_SELF        = 8;
    internal const uint CSSLOT_LAUNCH_CONSTRAINT_PARENT      = 9;
    internal const uint CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE = 10;
    internal const uint CSSLOT_LIBRARY_CONSTRAINT            = 11;
    internal const uint CSSLOT_ALTERNATE_CODEDIRECTORIES     = 0x1000;
    internal const uint CSSLOT_ALTERNATE_CODEDIRECTORIES1    = 0x1001;
    internal const uint CSSLOT_ALTERNATE_CODEDIRECTORIES2    = 0x1002;
    internal const uint CSSLOT_ALTERNATE_CODEDIRECTORIES3    = 0x1003;
    internal const uint CSSLOT_ALTERNATE_CODEDIRECTORIES4    = 0x1004;
    internal const uint CSSLOT_ALTERNATE_CODEDIRECTORY_MAX   = 5;
    internal const uint CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT =
        CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX;
    internal const uint CSSLOT_CMS_SIGNATURE = 0x10000;
    internal const uint CSSLOT_HASHABLE_ENTRIES_MAX = CSSLOT_LIBRARY_CONSTRAINT;
    // @formatter:on
  }
}