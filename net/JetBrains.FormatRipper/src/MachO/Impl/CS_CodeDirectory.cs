using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct CS_CodeDirectory
  {
    internal UInt32 magic; /* magic number (CSMAGIC_CODEDIRECTORY) */
    internal UInt32 length; /* total length of CodeDirectory blob */
    internal UInt32 version; /* compatibility version */
    internal UInt32 flags; /* setup and mode flags */
    internal UInt32 hashOffset; /* offset of hash slot element at index zero */
    internal UInt32 identOffset; /* offset of identifier string */
    internal UInt32 nSpecialSlots; /* number of special hash slots */
    internal UInt32 nCodeSlots; /* number of ordinary (code) hash slots */
    internal UInt32 codeLimit; /* limit to main image signature range */
    internal Byte hashSize; /* size of each hash in bytes */
    internal Byte hashType; /* type of hash (cdHashType* constants) */
    internal Byte spare1; /* unused (must be zero) */
    internal Byte pageSize; /* log2(page size in bytes); 0 => infinite */
    internal UInt32 spare2; /* unused (must be zero) */
  }
}