using System;
using System.Collections.Generic;
using System.IO;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.Dmg
{
  public sealed class DmgFile
  {
    private static readonly byte[] ExpectedSignature = new byte[] { 0x6b, 0x6f, 0x6c, 0x79 }; // 'koly'

    public static readonly long
      CodeSignaturePointerOffset = 296L; // counted according to the UDIFResourceFile structure

    public readonly SignatureData? SignatureData;
    public readonly ComputeHashInfo ComputeHashInfo;
    public readonly DmgFileMetadata Metadata;

    public static unsafe bool Is(Stream stream)
    {
      stream.Position = stream.Length - sizeof(UDIFResourceFile);
      UDIFResourceFile header;
      StreamUtil.ReadBytes(stream, (byte*)&header, sizeof(UDIFResourceFile));
      return MemoryUtil.ArraysEqual(header.udifSignature, 4, ExpectedSignature);
    }

    public static DmgFile Parse(Stream stream)
    {
      return new DmgFile(stream);
    }

    private unsafe DmgFile(Stream stream)
    {
      stream.Position = stream.Length - sizeof(UDIFResourceFile);
      UDIFResourceFile headerBuffer;
      StreamUtil.ReadBytes(stream, (byte*)&headerBuffer, sizeof(UDIFResourceFile));
      var header = headerBuffer;

      if (!MemoryUtil.ArraysEqual(header.udifSignature, ExpectedSignature.Length, ExpectedSignature))
        throw new FormatException("Invalid KOLY magic");


      var signatureOffset = (long)MemoryUtil.GetBeU8(header.CodeSignatureOffset);
      var signatureLength = (long)MemoryUtil.GetBeU8(header.CodeSignatureLength);

      Metadata = new DmgFileMetadata(stream.Length, new StreamRange(signatureOffset, signatureLength));

      byte[]? codeDirectoryBlob = null;
      byte[]? cmsSignatureBlob = null;
      if (MemoryUtil.GetBeU8(header.CodeSignatureOffset) > 0)
      {
        stream.Position = (long)MemoryUtil.GetBeU8(header.CodeSignatureOffset);

        CS_SuperBlob cssb;
        StreamUtil.ReadBytes(stream, (byte*)&cssb, sizeof(CS_SuperBlob));

        if ((CSMAGIC)MemoryUtil.GetBeU4(cssb.magic) != CSMAGIC.CSMAGIC_EMBEDDED_SIGNATURE)
          throw new FormatException("Invalid Mach-O code embedded signature magic");

        Metadata.codeSignatureInfo.magic = MemoryUtil.GetBeU4(cssb.magic);

        var csLength = MemoryUtil.GetBeU4(cssb.length);
        Metadata.codeSignatureInfo.length = csLength;

        if (csLength < sizeof(CS_SuperBlob))
          throw new FormatException("Too small Mach-O code signature super blob");

        var csCount = MemoryUtil.GetBeU4(cssb.count);
        Metadata.codeSignatureInfo.superBlobCount = (int)csCount;
        Metadata.codeSignatureInfo.superBlobStart = signatureOffset;

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
                Metadata.codeSignatureInfo.blobs.Add(
                  new Blob(
                    MemoryUtil.GetBeU4(csbi.type),
                    MemoryUtil.GetBeU4(csbi.offset),
                    CSMAGIC_CONSTS.CODEDIRECTORY,
                    MemoryUtil.GetBeU4(cscd.magic),
                    codeDirectoryBlob
                  )
                );
              }
                break;
              default:
              {
                CS_Blob csb;
                MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csb, sizeof(CS_Blob));

                var csbLength = MemoryUtil.GetBeU4(csb.length);
                if (csbLength < sizeof(CS_Blob))
                  throw new FormatException("Too small Mach-O cms signature blob length");

                var data = MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Blob),
                  checked((int)csbLength) - sizeof(CS_Blob));
                var length = data.Length;

                if (MemoryUtil.GetBeU4(csbi.type) == CSSLOT.CSSLOT_CMS_SIGNATURE)
                {
                  cmsSignatureBlob = data;
                  data = new byte[0];
                }

                Metadata.codeSignatureInfo.blobs.Add(
                  new Blob(
                    MemoryUtil.GetBeU4(csbi.type),
                    MemoryUtil.GetBeU4(csbi.offset),
                    (CSMAGIC_CONSTS)MemoryUtil.GetBeU4(csbi.type),
                    MemoryUtil.GetBeU4(csb.magic),
                    data,
                    length: length
                  )
                );
              }
                break;
            }
          }
        }

        SignatureData = new SignatureData(codeDirectoryBlob, cmsSignatureBlob);
      }

      var orderedIncludeRanges = new List<StreamRange>();
      if (HasSignature())
      {
        orderedIncludeRanges.Add(new StreamRange(0, signatureOffset));

        var dataBeforeUDIFLength =
          stream.Length - (signatureOffset + signatureLength) - sizeof(UDIFResourceFile);

        if (dataBeforeUDIFLength > 0)
        {
          orderedIncludeRanges.Add(
            new StreamRange(signatureOffset + signatureLength, dataBeforeUDIFLength));
        }
      }
      else
      {
        orderedIncludeRanges.Add(new StreamRange(0, stream.Length - sizeof(UDIFResourceFile)));
      }

      ComputeHashInfo = new ComputeHashInfo(0, orderedIncludeRanges, 0);
    }

    public bool HasSignature() => SignatureData != null;
  }
}