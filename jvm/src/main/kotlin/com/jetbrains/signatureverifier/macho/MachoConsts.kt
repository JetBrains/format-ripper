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
  val CSSLOT_CODEDIRECTORY = 0// slot index for CodeDirectory
  val CSSLOT_CMS_SIGNATURE = 0x10000// slot index for CmsSignedData
  val CSMAGIC_BLOBWRAPPER = 0xfade0b01//used for the cms blob
  val CSMAGIC_CODEDIRECTORY = 0xfade0c02//used for the CodeDirectory blob
  val LC_SEGMENT = 1
  val LC_SEGMENT_64 = 0x19
  val LC_CODE_SIGNATURE = 0x1D
}

