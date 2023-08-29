using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.Compound.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public unsafe struct CompoundFileHeader
  {
    internal fixed Byte HeaderSignature[Declarations.HeaderSignatureSize];
    internal Guid HeaderClsid;
    internal UInt16 MinorVersion;
    internal UInt16 MajorVersion;
    internal UInt16 ByteOrder;
    internal UInt16 SectorShift;
    internal UInt16 MiniSectorShift;
    internal fixed Byte Reserved[6];
    internal UInt32 NumberOfDirectorySectors;
    internal UInt32 NumberOfFatSectors;
    internal UInt32 FirstDirectorySectorLocation;
    internal UInt32 TransactionSignatureNumber;
    internal UInt32 MiniStreamCutoffSize;
    internal UInt32 FirstMiniFatSectorLocation;
    internal UInt32 NumberOfMiniFatSectors;
    internal UInt32 FirstDiFatSectorLocation;
    internal UInt32 NumberOfDiFatSectors;
  }

  // Used to serialize CompoundFileHeader, since Newtonsoft can't serialize structs
  public class CompoundFileHeaderData
  {
    public byte[] HeaderSignature { get; }
    public Guid HeaderClsid { get; }
    public ushort MinorVersion { get; }
    public ushort MajorVersion { get; }
    public ushort ByteOrder { get; }
    public ushort SectorShift { get; }
    public ushort MiniSectorShift { get; }
    public byte[] Reserved { get; }
    public uint NumberOfDirectorySectors { get; }
    public uint NumberOfFatSectors { get; }
    public uint FirstDirectorySectorLocation { get; }
    public uint TransactionSignatureNumber { get; }
    public uint MiniStreamCutoffSize { get; }
    public uint FirstMiniFatSectorLocation { get; }
    public uint NumberOfMiniFatSectors { get; }
    public uint FirstDiFatSectorLocation { get; }
    public uint NumberOfDiFatSectors { get; }

    public static CompoundFileHeaderData GetInstance(CompoundFileHeader compoundFileHeader)
    {
      var headerSignature = new byte[Declarations.HeaderSignatureSize];
      var reserved = new byte[6];
      unsafe
      {
        for (int i = 0; i < Declarations.HeaderSignatureSize; i++)
          headerSignature[i] = compoundFileHeader.HeaderSignature[i];

        for (int i = 0; i < 6; i++)
          reserved[i] = compoundFileHeader.Reserved[i];
      }

      return new CompoundFileHeaderData(
        headerSignature,
        compoundFileHeader.HeaderClsid,
        compoundFileHeader.MinorVersion,
        compoundFileHeader.MajorVersion,
        compoundFileHeader.ByteOrder,
        compoundFileHeader.SectorShift,
        compoundFileHeader.MiniSectorShift,
        reserved,
        compoundFileHeader.NumberOfDirectorySectors,
        compoundFileHeader.NumberOfFatSectors,
        compoundFileHeader.FirstDirectorySectorLocation,
        compoundFileHeader.TransactionSignatureNumber,
        compoundFileHeader.MiniStreamCutoffSize,
        compoundFileHeader.FirstMiniFatSectorLocation,
        compoundFileHeader.NumberOfMiniFatSectors,
        compoundFileHeader.FirstDiFatSectorLocation,
        compoundFileHeader.NumberOfDiFatSectors
      );
    }


    public CompoundFileHeaderData(byte[] headerSignature, Guid headerClsid, ushort minorVersion, ushort majorVersion,
      ushort byteOrder, ushort sectorShift, ushort miniSectorShift, byte[] reserved, uint numberOfDirectorySectors,
      uint numberOfFatSectors, uint firstDirectorySectorLocation, uint transactionSignatureNumber,
      uint miniStreamCutoffSize, uint firstMiniFatSectorLocation, uint numberOfMiniFatSectors,
      uint firstDiFatSectorLocation, uint numberOfDiFatSectors)
    {
      HeaderSignature = headerSignature;
      HeaderClsid = headerClsid;
      MinorVersion = minorVersion;
      MajorVersion = majorVersion;
      ByteOrder = byteOrder;
      SectorShift = sectorShift;
      MiniSectorShift = miniSectorShift;
      Reserved = reserved;
      NumberOfDirectorySectors = numberOfDirectorySectors;
      NumberOfFatSectors = numberOfFatSectors;
      FirstDirectorySectorLocation = firstDirectorySectorLocation;
      TransactionSignatureNumber = transactionSignatureNumber;
      MiniStreamCutoffSize = miniStreamCutoffSize;
      FirstMiniFatSectorLocation = firstMiniFatSectorLocation;
      NumberOfMiniFatSectors = numberOfMiniFatSectors;
      FirstDiFatSectorLocation = firstDiFatSectorLocation;
      NumberOfDiFatSectors = numberOfDiFatSectors;
    }
  }
}