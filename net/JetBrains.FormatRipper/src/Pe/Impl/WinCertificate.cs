using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal static class WinCertificate
  {
    internal const ushort WIN_CERT_REVISION_1_0 = 0x0100;
    internal const ushort WIN_CERT_REVISION_2_0 = 0x0200;

    // @formatter:off
    internal const ushort WIN_CERT_TYPE_X509             = 0x0001; // bCertificate contains an X.509 Certificate
    internal const ushort WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002; // bCertificate contains a PKCS SignedData structure
    internal const ushort WIN_CERT_TYPE_RESERVED_1       = 0x0003; // Reserved
    internal const ushort WIN_CERT_TYPE_TS_STACK_SIGNED  = 0x0004; // Terminal Server Protocol Stack Certificate signing
    // @formatter:on
  }
}