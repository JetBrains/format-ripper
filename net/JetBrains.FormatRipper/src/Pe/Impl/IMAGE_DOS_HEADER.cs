using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.Pe.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal unsafe struct IMAGE_DOS_HEADER
  {
    internal UInt16 e_magic; // Magic number
    internal UInt16 e_cblp; // Bytes on last page of file
    internal UInt16 e_cp; // Pages in file
    internal UInt16 e_crlc; // Relocations
    internal UInt16 e_cparhdr; // Size of header in paragraphs
    internal UInt16 e_minalloc; // Minimum extra paragraphs needed
    internal UInt16 e_maxalloc; // Maximum extra paragraphs needed
    internal UInt16 e_ss; // Initial (relative) SS value
    internal UInt16 e_sp; // Initial SP value
    internal UInt16 e_csum; // Checksum
    internal UInt16 e_ip; // Initial IP value
    internal UInt16 e_cs; // Initial (relative) CS value
    internal UInt16 e_lfarlc; // File address of relocation table
    internal UInt16 e_ovno; // Overlay number
    internal fixed UInt16 e_res[4]; // Reserved words
    internal UInt16 e_oemid; // OEM identifier (for e_oeminfo)
    internal UInt16 e_oeminfo; // OEM information; e_oemid specific
    internal fixed UInt16 e_res2[10]; // Reserved words
    internal UInt32 e_lfanew; // File address of new exe header
  }
}