using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl;

[SuppressMessage("ReSharper", "IdentifierTypo")]
[SuppressMessage("ReSharper", "InconsistentNaming")]
[SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
[StructLayout(LayoutKind.Sequential)]
internal struct CS_Entitlements
{
  internal UInt32 magic; /* magic number (CSMAGIC_EMBEDDED_ENTITLEMENTS or CSMAGIC_EMBEDDED_ENTITLEMENTS_DER) */
  internal UInt32 length; /* total length of the Entitlements blob */
}