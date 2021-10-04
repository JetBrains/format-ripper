namespace JetBrains.SignatureVerifier.Macho
{
  public static class MachoConsts
  {
    public const uint FAT_MAGIC = 0xCAFEBABE;
    public const uint FAT_MAGIC_64 = 0xCAFEBABF;
    public const uint FAT_CIGAM = 0xBEBAFECA;
    public const uint FAT_CIGAM_64 = 0xBFBAFECA;

    public const uint MH_MAGIC = 0xFEEDFACE;
    public const uint MH_MAGIC_64 = 0xFEEDFACF;
    public const uint MH_CIGAM = 0xCEFAEDFE;
    public const uint MH_CIGAM_64 = 0xCFFAEDFE;

    public const uint CSSLOT_CODEDIRECTORY = 0; // slot index for CodeDirectory
    public const uint CSSLOT_CMS_SIGNATURE = 0x10000; // slot index for CmsSignedData
    public const uint CSMAGIC_BLOBWRAPPER = 0xfade0b01; //used for the cms blob
    public const uint CSMAGIC_CODEDIRECTORY = 0xfade0c02; //used for the CodeDirectory blob
  }
}