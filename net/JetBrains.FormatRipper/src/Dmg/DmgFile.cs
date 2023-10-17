using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Xml.Linq;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.Dmg
{
  public sealed class DmgFile
  {
    private static readonly byte[] ExpectedSignature = new byte[] { 0x6b, 0x6f, 0x6c, 0x79 }; // 'koly'
    public readonly SignatureData SignatureData;
    public readonly bool HasSignature;
    public readonly ComputeHashInfo? ComputeHashInfo = null;
    public readonly StreamRange PList;
    public readonly UDIFChecksum MasterChecksum;
    public readonly UDIFChecksum DataChecksum;
    public readonly byte[]? PListData;
    public readonly StreamRange DataFork;
    public readonly StreamRange RsrcFork;
    private static readonly unsafe int HeaderSize = sizeof(UDIFResourceFile);

    [Flags]
    public enum Mode : uint
    {
      Default = 0x0,
      SignatureData = 0x1,
      ComputeHashInfo = 0x2,
      PList = 0x3
    }

    public static unsafe bool Is(Stream stream)
    {
      if (stream.Length < HeaderSize)
        return false;

      stream.Position = stream.Length - HeaderSize;
      UDIFResourceFile header;
      StreamUtil.ReadBytes(stream, (byte*)&header, HeaderSize);
      return MemoryUtil.ArraysEqual(header.udifSignature, ExpectedSignature.Length, ExpectedSignature);
    }

    public static DmgFile Parse(Stream stream, Mode mode = Mode.Default)
    {
      return new DmgFile(stream, mode);
    }

    private unsafe DmgFile(Stream stream, Mode mode)
    {
      UDIFResourceFile header = GetHeader(stream);

      if (MemoryUtil.GetBeU4(header.HeaderSize) != HeaderSize)
        throw new FormatException("Invalid header size");

      if (!MemoryUtil.ArraysEqual(header.udifSignature, ExpectedSignature.Length, ExpectedSignature))
        throw new FormatException("Invalid KOLY magic");

      if (MemoryUtil.GetBeU8(header.CodeSignatureOffset) > 0)
      {
        HasSignature = true;
        if ((Mode.SignatureData & mode) == Mode.SignatureData)
          SignatureData = ReadSignatureData(header, stream);
      }

      MasterChecksum = header.MasterChecksum;
      DataChecksum = header.DataChecksum;

      PList = new StreamRange((long)MemoryUtil.GetBeU8(header.PlistOffset),
        (long)MemoryUtil.GetBeU8(header.PlistLength));
      DataFork = new StreamRange((long)MemoryUtil.GetBeU8(header.DataForkOffset),
        (long)MemoryUtil.GetBeU8(header.DataForkLength));
      RsrcFork = new StreamRange((long)MemoryUtil.GetBeU8(header.RsrcForkOffset),
        (long)MemoryUtil.GetBeU8(header.RsrcForkLength));

      if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
      {
        var orderedIncludeRanges = SetHashRanges(header, stream);
        ComputeHashInfo = new ComputeHashInfo(0, orderedIncludeRanges, 0);
      }

      if ((mode & Mode.PList) == Mode.PList)
      {
        if (PList.Position > 0)
        {
          stream.Position = PList.Position;
          PListData = StreamUtil.ReadBytes(stream, checked((int)PList.Size));
        }
      }
    }

    private unsafe UDIFResourceFile GetHeader(Stream stream)
    {
      if (stream.Length < HeaderSize)
        throw new FormatException("Stream is less then header size");

      stream.Position = stream.Length - HeaderSize;
      UDIFResourceFile headerBuffer;
      StreamUtil.ReadBytes(stream, (byte*)&headerBuffer, sizeof(UDIFResourceFile));
      return headerBuffer;
    }

    private List<StreamRange> SetHashRanges(UDIFResourceFile header, Stream stream)
    {
      var orderedIncludeRanges = new List<StreamRange>();
      if (HasSignature)
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

    private unsafe SignatureData ReadSignatureData(UDIFResourceFile header, Stream stream)
    {
      byte[]? codeDirectoryBlob = null;
      byte[]? cmsSignatureBlob = null;
      stream.Position = checked((long)MemoryUtil.GetBeU8(header.CodeSignatureOffset));

      CS_SuperBlob csSuperBlob = GetCssb(stream);
      var csLength = MemoryUtil.GetBeU4(csSuperBlob.length);

      if (csLength < sizeof(CS_SuperBlob))
        throw new FormatException("Too small Mach-O code signature super blob");

      var csCount = MemoryUtil.GetBeU4(csSuperBlob.count);
      ProcessSignatureBlobs(csCount, csLength, ref codeDirectoryBlob, ref cmsSignatureBlob, stream);

      return new SignatureData(codeDirectoryBlob, cmsSignatureBlob);
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