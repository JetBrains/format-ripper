using System;
using System.Collections.Generic;
using System.IO;
using JetBrains.FormatRipper.Dmg.Impl;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.Dmg
{
  public sealed class DmgFile
  {
    public readonly bool HasSignature;
    public readonly SignatureData SignatureData;
    public readonly IEnumerable<HashVerificationUnit> HashVerificationUnits;
    public readonly IEnumerable<CDHash> CDHashes;
    public readonly IDmgSignatureTransferData? SignatureTransferData;

    [Flags]
    public enum Mode : uint
    {
      Default = 0x0,
      SignatureData = 0x1
    }

    private DmgFile(bool hasSignature,
      SignatureData signatureData,
      IEnumerable<HashVerificationUnit> hashVerificationUnits,
      IEnumerable<CDHash> cdHashes,
      IDmgSignatureTransferData? signatureTransferData)
    {
      HasSignature = hasSignature;
      SignatureData = signatureData;
      SignatureTransferData = signatureTransferData;
      HashVerificationUnits = hashVerificationUnits;
      CDHashes = cdHashes;
    }

    public static unsafe bool Is(Stream stream)
    {
      if (stream.Length < sizeof(UDIF))
        return false;

      stream.Seek(-sizeof(UDIF), SeekOrigin.End);

      UDIF udif;
      StreamUtil.ReadBytes(stream, (byte*)&udif, sizeof(UDIF));

      if ((DmgMagic)MemoryUtil.GetBeU4(udif.Magic) != DmgMagic.KOLY)
        return false;

      if (MemoryUtil.GetBeU4(udif.HeaderSize) != sizeof(UDIF))
        return false;

      ulong streamLength = checked((ulong)stream.Length);

      if (udif.PlistOffset == 0 || udif.PlistLength == 0)
        return false;

      if (MemoryUtil.GetBeU8(udif.PlistOffset) + MemoryUtil.GetBeU8(udif.PlistLength) > streamLength)
        return false;

      if (MemoryUtil.GetBeU8(udif.CodeSignatureOffset) + MemoryUtil.GetBeU8(udif.CodeSignatureLength) > streamLength)
        return false;

      return true;
    }

    public static unsafe DmgFile Parse(Stream stream, Mode mode = Mode.Default)
    {
      if (stream.Length < sizeof(UDIF))
        throw new ArgumentException("Provided stream is too short to be a valid DMG file");

      stream.Seek(-sizeof(UDIF), SeekOrigin.End);

      UDIF udif;
      StreamUtil.ReadBytes(stream, (byte*)&udif, sizeof(UDIF));

      if ((DmgMagic)MemoryUtil.GetBeU4(udif.Magic) != DmgMagic.KOLY)
        throw new FormatException("Invalid DMG file UDIF structure magic");

      ulong signatureOffset = MemoryUtil.GetBeU8(udif.CodeSignatureOffset);
      ulong signatureLength = MemoryUtil.GetBeU8(udif.CodeSignatureLength);

      if (signatureOffset + signatureLength > (ulong)stream.Length)
        throw new FormatException($"Invalid signature position. Signature position ({signatureOffset}) + signature length ({signatureLength}) is greater that stream length ({stream.Length})");

      var hasSignature = signatureLength != 0;
      byte[]? codeDirectoryBlob = null;
      byte[]? cmsSignatureBlob = null;
      IDmgSignatureTransferData? signatureTransferData = null;
      List<HashVerificationUnit> hashVerificationUnits = new List<HashVerificationUnit>();
      List<CDHash> cdHashes = new List<CDHash>();

      if ((mode & Mode.SignatureData) == Mode.SignatureData && hasSignature)
      {
        var imageRange = new StreamRange(0, stream.Length);

        stream.Position = checked(imageRange.Position + (long)signatureOffset);

        signatureTransferData = new DmgSignatureTransferData()
        {
          SignatureOffset = checked((long)signatureOffset),
          SignatureLength = checked((long)signatureLength),
          SignatureBlob = StreamUtil.ReadBytes(stream, checked((int)signatureLength)),
        };

        stream.Position = checked(imageRange.Position + (long)signatureOffset);

        CS_SuperBlob cssb;
        StreamUtil.ReadBytes(stream, (byte*)&cssb, sizeof(CS_SuperBlob));
        if ((CSMAGIC)MemoryUtil.GetBeU4(cssb.magic) != CSMAGIC.CSMAGIC_EMBEDDED_SIGNATURE)
          throw new FormatException("Invalid DMG code embedded signature magic");
        var csLength = MemoryUtil.GetBeU4(cssb.length);
        if (csLength < sizeof(CS_SuperBlob))
          throw new FormatException("Too small DMG code signature super blob");

        var csCount = MemoryUtil.GetBeU4(cssb.count);
        fixed (byte* scBuf = StreamUtil.ReadBytes(stream, checked((int)csLength - sizeof(CS_SuperBlob))))
        {
          ComputeHashInfo[] specialSlotPositions = new ComputeHashInfo[CSSLOT.CSSLOT_HASHABLE_ENTRIES_MAX - 1];

          for (int superBlobEntryIndex = 0; superBlobEntryIndex < csCount; superBlobEntryIndex++)
          {
            var scPtr = scBuf + superBlobEntryIndex * sizeof(CS_BlobIndex);
            CS_BlobIndex csbi;
            MemoryUtil.CopyBytes(scPtr, (byte*)&csbi, sizeof(CS_BlobIndex));
            uint slotType = MemoryUtil.GetBeU4(csbi.type);

            if (slotType >= CSSLOT.CSSLOT_INFOSLOT && slotType <= CSSLOT.CSSLOT_LIBRARY_CONSTRAINT)
            {
              uint offset = MemoryUtil.GetBeU4(csbi.offset);
              var csOffsetPtr = scBuf + offset - sizeof(CS_SuperBlob);

              CS_Blob csb;
              MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csb, sizeof(CS_Blob));

              specialSlotPositions[slotType - 1] = new ComputeHashInfo(0, new[]
              {
                new StreamRange(checked(imageRange.Position + (long)signatureOffset + offset), MemoryUtil.GetBeU4(csb.length))
              }, 0);
            }
          }

          for (var scPtr = scBuf; csCount-- > 0; scPtr += sizeof(CS_BlobIndex))
          {
            CS_BlobIndex csbi;
            MemoryUtil.CopyBytes(scPtr, (byte*)&csbi, sizeof(CS_BlobIndex));
            uint offset = MemoryUtil.GetBeU4(csbi.offset);
            var csOffsetPtr = scBuf + offset - sizeof(CS_SuperBlob);
            uint slotType = MemoryUtil.GetBeU4(csbi.type);
            switch (slotType)
            {
              case CSSLOT.CSSLOT_CODEDIRECTORY:
              case CSSLOT.CSSLOT_ALTERNATE_CODEDIRECTORIES:
              case CSSLOT.CSSLOT_ALTERNATE_CODEDIRECTORIES1:
              case CSSLOT.CSSLOT_ALTERNATE_CODEDIRECTORIES2:
              case CSSLOT.CSSLOT_ALTERNATE_CODEDIRECTORIES3:
              case CSSLOT.CSSLOT_ALTERNATE_CODEDIRECTORIES4:
              {
                CS_CodeDirectory cscd;
                MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&cscd, sizeof(CS_CodeDirectory));
                if ((CSMAGIC)MemoryUtil.GetBeU4(cscd.magic) != CSMAGIC.CSMAGIC_CODEDIRECTORY)
                  throw new FormatException("Invalid DMG code directory signature magic");
                var cscdLength = MemoryUtil.GetBeU4(cscd.length);

                byte[] currentCodeDirectoryBlob = MemoryUtil.CopyBytes(csOffsetPtr, checked((int)cscdLength));

                if (slotType == CSSLOT.CSSLOT_CODEDIRECTORY)
                  codeDirectoryBlob = currentCodeDirectoryBlob;

                int codeSlots = checked((int)MemoryUtil.GetBeU4(cscd.nCodeSlots));
                int specialSlots = checked((int)MemoryUtil.GetBeU4(cscd.nSpecialSlots));
                uint zeroHashOffset = MemoryUtil.GetBeU4(cscd.hashOffset);
                long codeLimit = MemoryUtil.GetBeU4(cscd.codeLimit);
                int pageSize = cscd.pageSize > 0 ? 1 << cscd.pageSize : 0;
                string hashName = CS_HASHTYPE.GetHashName(cscd.hashType);

                var cdHash = new CDHash(hashName, new ComputeHashInfo(0, new[]
                {
                  new StreamRange(checked(imageRange.Position + (long)signatureOffset + offset), cscdLength)
                }, 0));

                cdHashes.Add(cdHash);

                for (int i = 0; i < codeSlots; i++)
                {
                  byte[] hash = new byte[cscd.hashSize];
                  Array.Copy(currentCodeDirectoryBlob, checked((int)zeroHashOffset + i * cscd.hashSize), hash, 0, cscd.hashSize);

                  long pageStart = i * pageSize;
                  long currentPageSize;
                  if (pageSize > 0)
                    currentPageSize = pageStart + pageSize > codeLimit ? codeLimit - pageStart : pageSize;
                  else
                    currentPageSize = codeLimit - pageStart;

                  var computeHashInfo = new ComputeHashInfo(0, new[]
                  {
                    new StreamRange(pageStart + imageRange.Position, currentPageSize)
                  }, 0);

                  hashVerificationUnits.Add(new HashVerificationUnit(hashName, hash, computeHashInfo));
                }

                for (uint i = 1; i <= specialSlots; i++)
                {
                  byte[] hash = new byte[cscd.hashSize];
                  Array.Copy(currentCodeDirectoryBlob, checked((int)(zeroHashOffset - i * cscd.hashSize)), hash, 0, cscd.hashSize);

                  if (specialSlotPositions[i - 1] != null)
                    hashVerificationUnits.Add(new HashVerificationUnit(hashName, hash, specialSlotPositions[i - 1]));
                }
              }
                break;
              case CSSLOT.CSSLOT_CMS_SIGNATURE:
              {
                CS_Blob csb;
                MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csb, sizeof(CS_Blob));
                if ((CSMAGIC)MemoryUtil.GetBeU4(csb.magic) != CSMAGIC.CSMAGIC_BLOBWRAPPER)
                  throw new FormatException("Invalid DMG blob wrapper signature magic");
                var csbLength = MemoryUtil.GetBeU4(csb.length);
                if (csbLength < sizeof(CS_Blob))
                  throw new FormatException("Too small DMG cms signature blob length");
                cmsSignatureBlob = MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Blob), checked((int)csbLength - sizeof(CS_Blob)));
              }
                break;
            }
          }
        }
      }

      return new DmgFile(hasSignature, new SignatureData(codeDirectoryBlob, cmsSignatureBlob), hashVerificationUnits, cdHashes, signatureTransferData);
    }
  }
}