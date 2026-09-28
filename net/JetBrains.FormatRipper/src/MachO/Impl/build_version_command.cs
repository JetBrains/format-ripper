using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl
{
  /* LC_BUILD_VERSION */
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct build_version_command
  {
    internal UInt32 cmd; /* LC_BUILD_VERSION */
    internal UInt32 cmdsize; /* sizeof(struct build_version_command) plus ntools * sizeof(struct build_tool_version) */
    internal UInt32 platform; /* platform */
    internal UInt32 minos; /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
    internal UInt32 sdk; /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
    internal UInt32 ntools; /* number of tool entries following this */
  }

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct build_tool_version
  {
    internal UInt32 tool; /* enum for the tool */
    internal UInt32 version; /* version number of the tool */
  }
}
