using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal enum CSMAGIC : uint
  {
    // @formatter:off
    CSMAGIC_REQUIREMENT           = 0xFADE0C00, /* single Requirement blob */
    CSMAGIC_REQUIREMENTS          = 0xFADE0C01, /* Requirements vector (internal requirements) */
    CSMAGIC_CODEDIRECTORY         = 0xFADE0C02, /* CodeDirectory blob */
    CSMAGIC_EMBEDDED_SIGNATURE    = 0xFADE0CC0, /* embedded form of signature data */
    CSMAGIC_DETACHED_SIGNATURE    = 0xFADE0CC1, /* multi-arch collection of embedded signatures */
    CSMAGIC_BLOBWRAPPER           = 0xFADE0B01, /* used for the cms blob */
    CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171,	/* embedded entitlements */
    // @formatter:on
  }
}