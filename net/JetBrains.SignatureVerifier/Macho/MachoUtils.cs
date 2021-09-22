using System.IO;

namespace JetBrains.SignatureVerifier.Macho
{
    class MachoUtils
    {
        // Note: See https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h
        // Note: See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

        public static bool IsFatMacho(uint magic) => magic == MachoConsts.FAT_MAGIC ||
                                                     magic == MachoConsts.FAT_MAGIC_64 ||
                                                     magic == MachoConsts.FAT_CIGAM ||
                                                     magic == MachoConsts.FAT_CIGAM_64;

        public static bool IsMacho(uint magic) => magic == MachoConsts.MH_MAGIC ||
                                                  magic == MachoConsts.MH_MAGIC_64 ||
                                                  magic == MachoConsts.MH_CIGAM ||
                                                  magic == MachoConsts.MH_CIGAM_64;

        public static byte[] ReadBlob(BinaryReader reader)
        {
            var magic = ReadUtils.ReadUInt32Le(reader, true);
            var length = ReadUtils.ReadUInt32Le(reader, true);
            return reader.ReadBytes((int)length);
        }

        public static byte[] ReadCodeDirectoryBlob(BinaryReader reader)
        {
            var magic = ReadUtils.ReadUInt32Le(reader, true); /* magic number (CSMAGIC_CODEDIRECTORY) */
            var length = ReadUtils.ReadUInt32Le(reader, true); /* total length of CodeDirectory blob */
            reader.BaseStream.Seek(-8, SeekOrigin.Current);
            return reader.ReadBytes((int)length);
        }
    }
}