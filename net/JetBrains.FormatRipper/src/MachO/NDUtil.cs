namespace JetBrains.FormatRipper.MachO
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/nlist.h

  // The equivalents for the GET_COMM_ALIGN, SET_COMM_ALIGN, GET_LIBRARY_ORDINAL and SET_LIBRARY_ORDINAL macros. The
  // alignment is meaningful for the common symbols only, which are the undefined(N_UNDF) external(N_EXT) entries with
  // the non-zero value holding the symbol size, and it is stored as a power of two between 2^1 and 2^15 where zero
  // means the natural alignment based on the symbol size. The library ordinal is meaningful for the undefined symbols
  // in the MH_TWOLEVEL images only.
  public static class NDUtil
  {
    public static byte GetCommAlign(ND desc) => (byte)((ushort)(desc & ND.COMM_ALIGN) >> 8);
    public static ND SetCommAlign(byte align, ND desc = 0) => (desc & ~ND.COMM_ALIGN) | ((ND)(align << 8) & ND.COMM_ALIGN);

    public static byte GetLibraryOrdinal(ND desc) => (byte)((ushort)(desc & ND.LIBRARY_ORDINAL) >> 8);
    public static ND SetLibraryOrdinal(byte ordinal, ND desc = 0) => (desc & ~ND.LIBRARY_ORDINAL) | ((ND)(ordinal << 8) & ND.LIBRARY_ORDINAL);
  }
}