using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/nlist.h
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/stab.h

  // The n_type field really contains four fields:
  //   unsigned char N_STAB:3, N_PEXT:1, N_TYPE:3, N_EXT:1;
  //   which are used via the following masks.
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [Flags]
  public enum NT : byte
  {
    // @formatter:off
    N_STAB = 0xe0, /* if any of these bits set, a symbolic debugging entry */
    N_PEXT = 0x10, /* private external symbol bit */
    N_TYPE = 0x0e, /* mask for the type bits */
    N_EXT  = 0x01, /* external symbol bit, set for external symbols */
    // @formatter:on

    /* Values for the N_TYPE(0x0e) bits */
    // @formatter:off
    N_UNDF = 0x0, /* undefined, n_sect == NO_SECT */
    N_ABS  = 0x2, /* absolute, n_sect == NO_SECT */
    N_INDR = 0xa, /* indirect */
    N_PBUD = 0xc, /* prebound undefined (defined in a dylib) */
    N_SECT = 0xe, /* defined in section number n_sect */
    // @formatter:on

    /* Values when any of the N_STAB(0xe0) bits are set */
    // @formatter:off
    N_GSYM    = 0x20, /* global symbol: name,,NO_SECT,type,0 */
    N_FNAME   = 0x22, /* procedure name (f77 kludge): name,,NO_SECT,0,0 */
    N_FUN     = 0x24, /* procedure: name,,n_sect,linenumber,address */
    N_STSYM   = 0x26, /* static symbol: name,,n_sect,type,address */
    N_LCSYM   = 0x28, /* .lcomm symbol: name,,n_sect,type,address */
    N_BNSYM   = 0x2e, /* begin nsect sym: 0,,n_sect,0,address */
    N_PC      = 0x30, /* global pascal symbol: name,,NO_SECT,subtype,line */
    N_AST     = 0x32, /* AST file path: name,,NO_SECT,0,0 */
    N_OPT     = 0x3c, /* emitted with gcc2_compiled and in gcc source */
    N_RSYM    = 0x40, /* register sym: name,,NO_SECT,type,register */
    N_SLINE   = 0x44, /* src line: 0,,n_sect,linenumber,address */
    N_ENSYM   = 0x4e, /* end nsect sym: 0,,n_sect,0,address */
    N_SSYM    = 0x60, /* structure elt: name,,NO_SECT,type,struct_offset */
    N_SO      = 0x64, /* source file name: name,,n_sect,0,address */
    N_OSO     = 0x66, /* object file name: name,,(see below),1,st_mtime */
    N_LIB     = 0x68, /* dynamic library file name: name,,NO_SECT,0,0 */
    N_LSYM    = 0x80, /* local sym: name,,NO_SECT,type,offset */
    N_BINCL   = 0x82, /* include file beginning: name,,NO_SECT,0,sum */
    N_SOL     = 0x84, /* #included file name: name,,n_sect,0,address */
    N_PARAMS  = 0x86, /* compiler parameters: name,,NO_SECT,0,0 */
    N_VERSION = 0x88, /* compiler version: name,,NO_SECT,0,0 */
    N_OLEVEL  = 0x8a, /* compiler -O level: name,,NO_SECT,0,0 */
    N_PSYM    = 0xa0, /* parameter: name,,NO_SECT,type,offset */
    N_EINCL   = 0xa2, /* include file end: name,,NO_SECT,0,0 */
    N_ENTRY   = 0xa4, /* alternate entry: name,,n_sect,linenumber,address */
    N_LBRAC   = 0xc0, /* left bracket: 0,,NO_SECT,nesting level,address */
    N_EXCL    = 0xc2, /* deleted include file: name,,NO_SECT,0,sum */
    N_RBRAC   = 0xe0, /* right bracket: 0,,NO_SECT,nesting level,address */
    N_BCOMM   = 0xe2, /* begin common: name,,NO_SECT,0,0 */
    N_ECOMM   = 0xe4, /* end common: name,,n_sect,0,0 */
    N_ECOML   = 0xe8, /* end common (local name): 0,,n_sect,0,address */
    N_LENG    = 0xfe  /* second stab entry with length information */
    // @formatter:on
  }
}