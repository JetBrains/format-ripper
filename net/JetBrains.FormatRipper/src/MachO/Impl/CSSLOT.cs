using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): See http://newosxbook.com/src.jl?tree=&file=/xnu-3247.1.106/bsd/sys/codesign.h
  
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
    internal const uint CSSLOT_CMS_SIGNATURE = 0x10000;
    // @formatter:on
  }
}