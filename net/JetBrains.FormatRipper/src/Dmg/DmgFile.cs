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
    private readonly Stream _stream;
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

    private DmgFile(Stream stream)
    {
      _stream = stream;
      UDIFResourceFile header = GetHeader(stream);
      IsValidFormat(header);

      if (MemoryUtil.GetBeU8(header.CodeSignatureOffset) > 0)
      {
        ReadSignatureData(header);
      }

      var orderedIncludeRanges = SetHashRanges(header);
      ComputeHashInfo = new ComputeHashInfo(0, orderedIncludeRanges, 0);
    }

    private unsafe UDIFResourceFile GetHeader(Stream stream)
    {
      stream.Position = stream.Length - HeaderSize;
      UDIFResourceFile headerBuffer;
      StreamUtil.ReadBytes(stream, (byte*)&headerBuffer, sizeof(UDIFResourceFile));
      return headerBuffer;
    }

    private unsafe void IsValidFormat(UDIFResourceFile header)
    {
      if (!MemoryUtil.ArraysEqual(header.udifSignature, ExpectedSignature.Length, ExpectedSignature))
        throw new FormatException("Invalid KOLY magic");
    }

    private List<StreamRange> SetHashRanges(UDIFResourceFile header)
    {
      var orderedIncludeRanges = new List<StreamRange>();
      if (HasSignature())
      {
        var signatureOffset = (long)MemoryUtil.GetBeU8(header.CodeSignatureOffset);
        var signatureLength = (long)MemoryUtil.GetBeU8(header.CodeSignatureLength);

        orderedIncludeRanges.Add(new StreamRange(0, signatureOffset));

        var dataBeforeUdifLength =
          _stream.Length - (signatureOffset + signatureLength) - HeaderSize;

        if (dataBeforeUdifLength > 0)
        {
          orderedIncludeRanges.Add(
            new StreamRange(signatureOffset + signatureLength, dataBeforeUdifLength));
        }
      }
      else
      {
        orderedIncludeRanges.Add(new StreamRange(0, _stream.Length - HeaderSize));
      }

      return orderedIncludeRanges;
    }

    private void ReadSignatureData(UDIFResourceFile header)
    {
      byte[]? codeDirectoryBlob = null;
      byte[]? cmsSignatureBlob = null;
      _stream.Position = (long)MemoryUtil.GetBeU8(header.CodeSignatureOffset);

      CS_SuperBlob csSuperBlob = GetCssb(_stream);
      var csLength = MemoryUtil.GetBeU4(csSuperBlob.length);

      ValidateCssbSize(csLength);

      var csCount = MemoryUtil.GetBeU4(csSuperBlob.count);
      ProcessSignatureBlobs(csCount, csLength, ref codeDirectoryBlob, ref cmsSignatureBlob);

      _signatureData = new SignatureData(codeDirectoryBlob, cmsSignatureBlob);
    }

    private unsafe CS_SuperBlob GetCssb(Stream stream)
    {
      CS_SuperBlob csSuperBlob;
      StreamUtil.ReadBytes(stream, (byte*)&csSuperBlob, sizeof(CS_SuperBlob));

      ValidateCssbMagic((CSMAGIC)MemoryUtil.GetBeU4(csSuperBlob.magic));

      return csSuperBlob;
    }

    private unsafe void ProcessSignatureBlobs(uint csCount, uint csLength,
      ref byte[]? codeDirectoryBlob, ref byte[]? cmsSignatureBlob)
    {
      fixed (byte* scBuf = StreamUtil.ReadBytes(_stream, checked((int)csLength - sizeof(CS_SuperBlob))))
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

      ValidateCodeDirectoryMagic((CSMAGIC)MemoryUtil.GetBeU4(cscd.magic));

      var cscdLength = MemoryUtil.GetBeU4(cscd.length);
      return MemoryUtil.CopyBytes(csOffsetPtr, checked((int)cscdLength));
    }

    private unsafe byte[] ProcessCmsSignature(byte* csOffsetPtr)
    {
      CS_Blob csb;
      MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csb, sizeof(CS_Blob));

      ValidateCsbMagic((CSMAGIC)MemoryUtil.GetBeU4(csb.magic));

      var csbLength = MemoryUtil.GetBeU4(csb.length);
      ValidateCsbSize(csbLength);

      return MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Blob),
        checked((int)csbLength) - sizeof(CS_Blob));
    }

    private void ValidateCodeDirectoryMagic(CSMAGIC magic)
    {
      if (magic != CSMAGIC.CSMAGIC_CODEDIRECTORY)
        throw new FormatException("Invalid Mach-O code directory signature magic");
    }

    private void ValidateCsbMagic(CSMAGIC magic)
    {
      if (magic != CSMAGIC.CSMAGIC_BLOBWRAPPER)
        throw new FormatException("Invalid Mach-O blob wrapper signature magic");
    }

    private unsafe void ValidateCsbSize(uint csbLength)
    {
      if (csbLength < sizeof(CS_Blob))
        throw new FormatException("Too small Mach-O cms signature blob length");
    }

    private void ValidateCssbMagic(CSMAGIC magic)
    {
      if (magic != CSMAGIC.CSMAGIC_EMBEDDED_SIGNATURE)
        throw new FormatException("Invalid Mach-O code embedded signature magic");
    }

    private unsafe void ValidateCssbSize(uint csLength)
    {
      if (csLength < sizeof(CS_SuperBlob))
        throw new FormatException("Too small Mach-O code signature super blob");
    }
  }
}