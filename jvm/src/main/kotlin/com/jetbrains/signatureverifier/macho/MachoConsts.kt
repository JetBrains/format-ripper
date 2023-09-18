package com.jetbrains.signatureverifier.macho

object MachoConsts {
  val FAT_MAGIC = 0xCAFEBABE
  val FAT_MAGIC_64 = 0xCAFEBABF
  val FAT_CIGAM = 0xBEBAFECA
  val FAT_CIGAM_64 = 0xBFBAFECA
  val MH_MAGIC = 0xFEEDFACE
  val MH_MAGIC_64 = 0xFEEDFACF
  val MH_CIGAM = 0xCEFAEDFE
  val MH_CIGAM_64 = 0xCFFAEDFE
  val CSSLOT_CODEDIRECTORY = 0 // slot index for CodeDirectory
  val CSSLOT_CMS_SIGNATURE = 0x10000 // slot index for CmsSignedData
  val CSSLOT_REQUIREMENTS = 2L
  val CSMAGIC_REQUIREMENTS = 0xfade0c01 // slot index for Requirements
  val CSMAGIC_CMS_SIGNATURE = 0xfade0b01
  val CSMAGIC_BLOBWRAPPER = 0xfade0b01 //used for the cms blob
  val CSMAGIC_CODEDIRECTORY = 0xfade0c02 //used for the CodeDirectory blob
  val CSMAGIC_SIGNATURE_DATA = 0xfade0cc0u
  val LC_SEGMENT = 1
  val LC_SEGMENT_64 = 0x19
  val LC_CODE_SIGNATURE = 0x1D
  val LINKEDIT_SEGMENT_NAME = arrayOf<Byte>(
    0x5f, 0x5f, 0x4c, 0x49, 0x4e, 0x4b, 0x45, 0x44, 0x49, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ).toByteArray()
}

enum class CSMAGIC {
  CODEDIRECTORY,
  INFOSLOT,
  REQUIREMENTS,
  RESOURCEDIR,
  APPLICATION,
  ENTITLEMENTS,
  ENTITLEMENTS_DER,
  ALTERNATE_CODEDIRECTORIES,
  CMS_SIGNATURE,
  UNKNOWN;

  companion object {
    /**
     * Returns an instance of a specific object based on the given csSlot value.
     *
     * @param csSlot The csSlot value used to determine the object instance.
     * @return CSMAGIC corresponding to the csSlot value.
     */
    fun getInstance(csSlot: UInt) = when (csSlot) {
      0u -> CODEDIRECTORY
      1u -> INFOSLOT
      2u -> REQUIREMENTS
      3u -> RESOURCEDIR
      4u -> APPLICATION
      5u -> ENTITLEMENTS
      7u -> ENTITLEMENTS_DER
      0x1000u -> ALTERNATE_CODEDIRECTORIES
      0x10000u -> CMS_SIGNATURE
      else -> UNKNOWN
    }
  }
}
