using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO.Impl;

[SuppressMessage("ReSharper", "IdentifierTypo")]
[SuppressMessage("ReSharper", "InconsistentNaming")]
internal static class CS_HASHTYPE
{
  // @formatter:off
  internal const uint CS_HASHTYPE_SHA1              = 1;
  internal const uint CS_HASHTYPE_SHA256            = 2;
  internal const uint CS_HASHTYPE_SHA256_TRUNCATED  = 3;
  internal const uint CS_HASHTYPE_SHA384            = 4;
  internal const uint CS_HASHTYPE_SHA512            = 5;
  // @formatter:on

  internal static string GetHashName(uint id) => id switch
  {
    CS_HASHTYPE_SHA1 => "SHA1",
    CS_HASHTYPE_SHA256 => "SHA256",
    CS_HASHTYPE_SHA256_TRUNCATED => "SHA256",
    CS_HASHTYPE_SHA384 => "SHA384",
    CS_HASHTYPE_SHA512 => "SHA512",
    _ => throw new NotSupportedException($"Hash function with id {id} is not supported"),
  };
}