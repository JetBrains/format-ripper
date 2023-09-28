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
    private SignatureData? _signatureData;
    public readonly ComputeHashInfo ComputeHashInfo;
    private static readonly unsafe int HeaderSize = sizeof(UDIFResourceFile);


    public bool HasSignature() => _signatureData != null;

    public SignatureData? SignatureData() => _signatureData;

    public static unsafe bool Is(Stream stream)
    {
      stream.Position = stream.Length - HeaderSize;
      UDIFResourceFile header;
      StreamUtil.ReadBytes(stream, (byte*)&header, HeaderSize);
      return MemoryUtil.ArraysEqual(header.udifSignature, ExpectedSignature.Length, ExpectedSignature);
    }

    public static DmgFile Parse(Stream stream)
    {
      return new DmgFile(stream);
    }

    private unsafe DmgFile(Stream stream)
    {
      UDIFResourceFile header = GetHeader(stream);

      if (!MemoryUtil.ArraysEqual(header.udifSignature, ExpectedSignature.Length, ExpectedSignature))
        throw new FormatException("Invalid KOLY magic");

      if (MemoryUtil.GetBeU8(header.CodeSignatureOffset) > 0)
      {
        ReadSignatureData(header, stream);
      }

      var orderedIncludeRanges = SetHashRanges(header, stream);
      ComputeHashInfo = new ComputeHashInfo(0, orderedIncludeRanges, 0);
    }

    private unsafe UDIFResourceFile GetHeader(Stream stream)
    {
      stream.Position = stream.Length - HeaderSize;
      UDIFResourceFile headerBuffer;
      StreamUtil.ReadBytes(stream, (byte*)&headerBuffer, sizeof(UDIFResourceFile));
      return headerBuffer;
    }

    private List<StreamRange> SetHashRanges(UDIFResourceFile header, Stream stream)
    {
      var orderedIncludeRanges = new List<StreamRange>();
      if (HasSignature())
      {
        var signatureOffset = (long)MemoryUtil.GetBeU8(header.CodeSignatureOffset);
        var signatureLength = (long)MemoryUtil.GetBeU8(header.CodeSignatureLength);

        orderedIncludeRanges.Add(new StreamRange(0, signatureOffset));

        var dataBeforeUdifLength =
          stream.Length - (signatureOffset + signatureLength) - HeaderSize;

        if (dataBeforeUdifLength > 0)
        {
          orderedIncludeRanges.Add(
            new StreamRange(signatureOffset + signatureLength, dataBeforeUdifLength));
        }
      }
      else
      {
        orderedIncludeRanges.Add(new StreamRange(0, stream.Length - HeaderSize));
      }

      return orderedIncludeRanges;
    }

    private unsafe void ReadSignatureData(UDIFResourceFile header, Stream stream)
    {
      byte[]? codeDirectoryBlob = null;
      byte[]? cmsSignatureBlob = null;
      stream.Position = (long)MemoryUtil.GetBeU8(header.CodeSignatureOffset);

      CS_SuperBlob csSuperBlob = GetCssb(stream);
      var csLength = MemoryUtil.GetBeU4(csSuperBlob.length);

      if (csLength < sizeof(CS_SuperBlob))
        throw new FormatException("Too small Mach-O code signature super blob");

      var csCount = MemoryUtil.GetBeU4(csSuperBlob.count);
      ProcessSignatureBlobs(csCount, csLength, ref codeDirectoryBlob, ref cmsSignatureBlob, stream);

      _signatureData = new SignatureData(codeDirectoryBlob, cmsSignatureBlob);
    }

    private unsafe CS_SuperBlob GetCssb(Stream stream)
    {
      CS_SuperBlob csSuperBlob;
      StreamUtil.ReadBytes(stream, (byte*)&csSuperBlob, sizeof(CS_SuperBlob));

      if ((CSMAGIC)MemoryUtil.GetBeU4(csSuperBlob.magic) != CSMAGIC.CSMAGIC_EMBEDDED_SIGNATURE)
        throw new FormatException("Invalid Mach-O code embedded signature magic");

      return csSuperBlob;
    }

    private unsafe void ProcessSignatureBlobs(uint csCount, uint csLength,
      ref byte[]? codeDirectoryBlob, ref byte[]? cmsSignatureBlob, Stream stream)
    {
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
              codeDirectoryBlob = ProcessCodeDirectory(csOffsetPtr);
              break;
            case CSSLOT.CSSLOT_CMS_SIGNATURE:
              cmsSignatureBlob = ProcessCmsSignature(csOffsetPtr);
              break;
          }
        }
      }
    }

    private unsafe byte[] ProcessCodeDirectory(byte* csOffsetPtr)
    {
      CS_CodeDirectory cscd;
      MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&cscd, sizeof(CS_CodeDirectory));


      if ((CSMAGIC)MemoryUtil.GetBeU4(cscd.magic) != CSMAGIC.CSMAGIC_CODEDIRECTORY)
        throw new FormatException("Invalid Mach-O code directory signature magic");

      var cscdLength = MemoryUtil.GetBeU4(cscd.length);
      return MemoryUtil.CopyBytes(csOffsetPtr, checked((int)cscdLength));
    }

    private unsafe byte[] ProcessCmsSignature(byte* csOffsetPtr)
    {
      CS_Blob csb;
      MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csb, sizeof(CS_Blob));


      if ((CSMAGIC)MemoryUtil.GetBeU4(csb.magic) != CSMAGIC.CSMAGIC_BLOBWRAPPER)
        throw new FormatException("Invalid Mach-O blob wrapper signature magic");

      var csbLength = MemoryUtil.GetBeU4(csb.length);
      if (csbLength < sizeof(CS_Blob))
        throw new FormatException("Too small Mach-O cms signature blob length");

      return MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Blob),
        checked((int)csbLength) - sizeof(CS_Blob));
    }
  }
}