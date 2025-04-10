using System;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.Pe.Impl;

namespace JetBrains.FormatRipper.Pe;

public class PeSignatureInjector
{
  internal const int SignatureAlignment = 8;

  /// <summary>
  /// Inject signature into a PE file
  /// </summary>
  /// <param name="sourceStream">Read-only stream of a file into which you want to inject a signature</param>
  /// <param name="outputStream">Stream for writing a result file with an injected signature</param>
  /// <param name="signatureTransferData">Signature transfer data to inject</param>
  /// <exception cref="ArgumentException">Thrown if output stream is not writeable</exception>
  /// <exception cref="FormatException">Thrown if input file has invalid format</exception>
  /// <exception cref="SignatureInjectionException">Thrown on signature transfer error. This usually happens when trying to transfer signatures between incompatible files.</exception>
  public static unsafe void InjectSignature(Stream sourceStream, Stream outputStream, IPeSignatureTransferData signatureTransferData)
  {
    if (!outputStream.CanWrite) throw new ArgumentException("Provided stream is not writeable");

    sourceStream.Position = 0;
    IMAGE_DOS_HEADER ids;
    StreamUtil.ReadBytes(sourceStream, (byte*)&ids, sizeof(IMAGE_DOS_HEADER));
    if (MemoryUtil.GetLeU2(ids.e_magic) != Magic.IMAGE_DOS_SIGNATURE)
      throw new FormatException("Invalid DOS magic");
    sourceStream.Position = MemoryUtil.GetLeU4(ids.e_lfanew);

    uint peMagic;
    StreamUtil.ReadBytes(sourceStream, (byte*)&peMagic, sizeof(uint));
    if (MemoryUtil.GetLeU4(peMagic) != Magic.IMAGE_NT_SIGNATURE)
      throw new FormatException("Invalid PE magic");

    long imageFileHeaderPosition = sourceStream.Position;

    sourceStream.Position = 0;
    StreamUtil.CopyBytes(sourceStream, outputStream, imageFileHeaderPosition);

    IMAGE_FILE_HEADER ifh;
    StreamUtil.ReadBytes(sourceStream, (byte*)&ifh, sizeof(IMAGE_FILE_HEADER));
    ifh.TimeDateStamp = MemoryUtil.GetLeU4(signatureTransferData.TimeDateStamp);
    StreamUtil.WriteBytes(outputStream, (byte*)&ifh, sizeof(IMAGE_FILE_HEADER));

    ushort iohMagic;
    StreamUtil.ReadBytes(sourceStream, (byte*)&iohMagic, sizeof(ushort));
    StreamUtil.WriteBytes(outputStream, (byte*)&iohMagic, sizeof(ushort));
    uint numberOfRvaAndSizes = 0;
    switch (MemoryUtil.GetLeU2(iohMagic))
      {
      case Magic.IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        {
          if (MemoryUtil.GetLeU4(ifh.SizeOfOptionalHeader) < sizeof(IMAGE_OPTIONAL_HEADER32))
            throw new FormatException("Invalid 32-bit option header size");

          IMAGE_OPTIONAL_HEADER32 ioh;
          StreamUtil.ReadBytes(sourceStream, (byte*)&ioh, sizeof(IMAGE_OPTIONAL_HEADER32));
          numberOfRvaAndSizes = Math.Max(MemoryUtil.GetLeU4(ioh.NumberOfRvaAndSizes), ImageDirectory.IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
          ioh.CheckSum = MemoryUtil.GetLeU4(signatureTransferData.CheckSum);
          StreamUtil.WriteBytes(outputStream, (byte*)&ioh, sizeof(IMAGE_OPTIONAL_HEADER32));
        }
        break;
      case Magic.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        {
          if (MemoryUtil.GetLeU4(ifh.SizeOfOptionalHeader) < sizeof(IMAGE_OPTIONAL_HEADER64))
            throw new FormatException("Invalid 64-bit option header size");
          IMAGE_OPTIONAL_HEADER64 ioh;
          StreamUtil.ReadBytes(sourceStream, (byte*)&ioh, sizeof(IMAGE_OPTIONAL_HEADER64));
          numberOfRvaAndSizes = Math.Max(MemoryUtil.GetLeU4(ioh.NumberOfRvaAndSizes), ImageDirectory.IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
          ioh.CheckSum = MemoryUtil.GetLeU4(signatureTransferData.CheckSum);
          StreamUtil.WriteBytes(outputStream, (byte*)&ioh, sizeof(IMAGE_OPTIONAL_HEADER64));
        }
        break;
      default:
        throw new FormatException("Unsupported PE image optional header");
      }

    long existingSignatureOffset = 0;

    int rvaSize = checked((int)numberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY));

    fixed (IMAGE_DATA_DIRECTORY* iddsBuf = new IMAGE_DATA_DIRECTORY[numberOfRvaAndSizes])
    {
      StreamUtil.ReadBytes(sourceStream, (byte*)iddsBuf, rvaSize);
      existingSignatureOffset = MemoryUtil.GetLeU4(iddsBuf[ImageDirectory.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
      iddsBuf[ImageDirectory.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = MemoryUtil.GetLeU4(signatureTransferData.SignatureBlobOffset);
      iddsBuf[ImageDirectory.IMAGE_DIRECTORY_ENTRY_SECURITY].Size = MemoryUtil.GetLeU4(signatureTransferData.SignatureBlobSize);

      StreamUtil.WriteBytes(outputStream, (byte*)iddsBuf, rvaSize);
    }

    long payloadEndOffset = existingSignatureOffset != 0 ? existingSignatureOffset : sourceStream.Length;

    long signaturePadding = signatureTransferData.SignatureBlobOffset - payloadEndOffset;
    if (signaturePadding < 0)
      throw new SignatureInjectionException($"Target file content length ({payloadEndOffset} bytes) is bigger than the desired signature start offset ({signatureTransferData.SignatureBlobOffset} bytes).");

    if (signaturePadding >= SignatureAlignment)
      throw new SignatureInjectionException($"The difference between unsigned file size ({payloadEndOffset} bytes) and the desired signature start offset ({signatureTransferData.SignatureBlobOffset} bytes) is bigger than maximum allowed padding size {SignatureAlignment-1} bytes");

    StreamUtil.CopyBytes(sourceStream, outputStream, payloadEndOffset - sourceStream.Position);

    if (signaturePadding > 0)
    {
      var padding = new byte[signaturePadding];
      outputStream.Write(padding, 0, padding.Length);
    }

    WIN_CERTIFICATE wc = new WIN_CERTIFICATE()
    {
      dwLength = MemoryUtil.GetLeU4(signatureTransferData.SignatureBlobSize),
      wRevision = MemoryUtil.GetLeU2(signatureTransferData.CertificateRevision),
      wCertificateType = MemoryUtil.GetLeU2(signatureTransferData.CertificateType),
    };

    StreamUtil.WriteBytes(outputStream, (byte*)&wc, sizeof(WIN_CERTIFICATE));
    outputStream.Write(signatureTransferData.SignatureBlob, 0, signatureTransferData.SignatureBlob.Length);
  }
}