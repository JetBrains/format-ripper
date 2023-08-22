using System;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.Dmg
{
  public sealed class DmgFile
  {
    static byte[] epxectedSignature = new byte[] { 0x6b, 0x6f, 0x6c, 0x79 };
    private UDIFResourceFile Header;
    public readonly SignatureData? SignatureData;

    public static unsafe bool Is(Stream stream)
    {
      stream.Position = stream.Length - 512;
      UDIFResourceFile header;
      StreamUtil.ReadBytes(stream, (byte*)&header, sizeof(UDIFResourceFile));
      return MemoryUtil.ArraysEqual(header.udifSignature, 4, epxectedSignature);
    }

    public static DmgFile Parse(Stream stream)
    {
      return new DmgFile(stream);
    }

    private unsafe DmgFile(Stream stream)
    {
      stream.Position = stream.Length - 512;
      UDIFResourceFile headerBuffer;
      StreamUtil.ReadBytes(stream, (byte*)&headerBuffer, sizeof(UDIFResourceFile));
      Header = headerBuffer;

      fixed (byte* p = Header.udifSignature)
      {
        if (!MemoryUtil.ArraysEqual(p, 4, epxectedSignature))
          throw new FormatException("Invalid KOLY magic");
      }

      byte[]? codeDirectoryBlob = null;
      byte[]? cmsSignatureBlob = null;
      if (MemoryUtil.GetBeU8(Header.CodeSignatureOffset) > 0)
      {
        stream.Position = (long)MemoryUtil.GetBeU8(Header.CodeSignatureOffset);

        CS_SuperBlob cssb;
        StreamUtil.ReadBytes(stream, (byte*)&cssb, sizeof(CS_SuperBlob));
        if ((CSMAGIC)MemoryUtil.GetBeU4(cssb.magic) != CSMAGIC.CSMAGIC_EMBEDDED_SIGNATURE)
          throw new FormatException("Invalid Mach-O code embedded signature magic");
        var csLength = MemoryUtil.GetBeU4(cssb.length);
        if (csLength < sizeof(CS_SuperBlob))
          throw new FormatException("Too small Mach-O code signature super blob");

        var csCount = MemoryUtil.GetBeU4(cssb.count);
        fixed (byte* scBuf = StreamUtil.ReadBytes(stream, checked((int)csLength - sizeof(CS_SuperBlob))))
        {
          for (var scPtr = scBuf; csCount-- > 0; scPtr += sizeof(CS_BlobIndex))
          {
            CS_BlobIndex csbi;
            MemoryUtil.CopyBytes(scPtr, (byte*)&csbi, sizeof(CS_BlobIndex));
            var csOffsetPtr = scBuf + MemoryUtil.GetBeU4(csbi.offset) - sizeof(CS_SuperBlob);
            switch (MemoryUtil.GetBeU4(csbi.type))
            {
              case CSSLOT.CSSLOT_CODEDIRECTORY:
              {
                CS_CodeDirectory cscd;
                MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&cscd, sizeof(CS_CodeDirectory));

                if ((CSMAGIC)MemoryUtil.GetBeU4(cscd.magic) != CSMAGIC.CSMAGIC_CODEDIRECTORY)
                  throw new FormatException("Invalid Mach-O code directory signature magic");

                var cscdLength = MemoryUtil.GetBeU4(cscd.length);
                codeDirectoryBlob = MemoryUtil.CopyBytes(csOffsetPtr, checked((int)cscdLength));
              }
                break;
              case CSSLOT.CSSLOT_CMS_SIGNATURE:
              {
                CS_Blob csb;
                MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csb, sizeof(CS_Blob));

                if ((CSMAGIC)MemoryUtil.GetBeU4(csb.magic) != CSMAGIC.CSMAGIC_BLOBWRAPPER)
                  throw new FormatException("Invalid Mach-O blob wrapper signature magic");

                var csbLength = MemoryUtil.GetBeU4(csb.length);
                if (csbLength < sizeof(CS_Blob))
                  throw new FormatException("Too small Mach-O cms signature blob length");

                cmsSignatureBlob = MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Blob),
                  checked((int)csbLength) - sizeof(CS_Blob));
              }
                break;
            }
          }
        }

        SignatureData = new SignatureData(codeDirectoryBlob, cmsSignatureBlob);
      }
    }

    public bool HasSignature() => SignatureData != null;
  }
}