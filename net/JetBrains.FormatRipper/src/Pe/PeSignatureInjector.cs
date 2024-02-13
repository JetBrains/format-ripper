using System;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.Pe.Impl;

namespace JetBrains.FormatRipper.Pe;

public class PeSignatureInjector
{
  internal const int SignatureAlignment = 8;

  public static unsafe void InjectSignature(Stream stream, PeFileSignature signature)
  {
    if (!stream.CanWrite) throw new ArgumentException("Provided file stream is not writeable");
    if (signature.SignatureBlob.Length + sizeof(WIN_CERTIFICATE) != signature.SignatureBlobSize)
      throw new ArgumentException($"Signature blob actual length ({signature.SignatureBlob.Length} bytes + {sizeof(WIN_CERTIFICATE)} bytes for the WIN_CERTIFICATE structure) doesn't match the value from IMAGE_DATA_DIRECTORY structure {signature.SignatureBlobSize}");

    var peFile = PeFile.Parse(stream, PeFile.Mode.SignatureData);

    if (peFile.HasSignature)
      ReplaceSignature(stream, peFile, signature);
    else
      AddSignature(stream, peFile, signature);
  }

  private static void AddSignature(Stream stream, PeFile peFile, PeFileSignature signature)
  {
    long lengthMismatch = signature.SignatureBlobOffset - stream.Length;
    if (lengthMismatch < 0)
      throw new SignatureInjectionException($"Target file size ({stream.Length} bytes) is bigger than the desired signature start offset ({signature.SignatureBlobOffset} bytes).");

    if (lengthMismatch >= SignatureAlignment)
      throw new SignatureInjectionException($"The difference between unsigned file size ({stream.Length} bytes) and the desired signature start offset ({signature.SignatureBlobOffset} bytes) is bigger than maximum allowed padding size {SignatureAlignment-1} bytes");

    //Write TimeDateStamp
    stream.Seek(peFile.TimeDateStampRange.Position, SeekOrigin.Begin);
    Write(stream, MemoryUtil.GetLeU4(signature.TimeDateStamp));

    //Write new PE file checksum
    stream.Seek(peFile.ChecksumRange.Position, SeekOrigin.Begin);
    Write(stream, MemoryUtil.GetLeU4(signature.ExpectedCrc));

    //Fill ImageDirectoryEntrySecurity
    stream.Seek(peFile.SecurityDataDirectoryRange.Position, SeekOrigin.Begin);
    Write(stream, MemoryUtil.GetLeU4(signature.SignatureBlobOffset));
    Write(stream, MemoryUtil.GetLeU4(signature.SignatureBlobSize));

    //Write signature to the end of the file
    stream.Seek(0, SeekOrigin.End);
    if (lengthMismatch > 0)
      Write(stream, new byte[lengthMismatch]);

    Write(stream, MemoryUtil.GetLeU4(signature.SignatureBlobSize));
    Write(stream, MemoryUtil.GetLeU2(signature.CertificateRevision));
    Write(stream, MemoryUtil.GetLeU2(signature.CertificateType));
    Write(stream, signature.SignatureBlob);
  }

  private static void ReplaceSignature(Stream stream, PeFile peFile, PeFileSignature signature)
  {
    if (peFile.Signature == null)
      throw new SignatureInjectionException("Error replacing signature: original signature is empty");
    if (peFile.Signature.SignatureBlobOffset != signature.SignatureBlobOffset)
      throw new SignatureInjectionException($"Error replacing signature: existing signature blob offset ({peFile.Signature.SignatureBlobOffset}) doesn't match the desired offset ({signature.SignatureBlobOffset})");

    //Write TimeDateStamp
    stream.Seek(peFile.TimeDateStampRange.Position, SeekOrigin.Begin);
    Write(stream, MemoryUtil.GetLeU4(signature.TimeDateStamp));

    //Write new PE file checksum
    stream.Seek(peFile.ChecksumRange.Position, SeekOrigin.Begin);
    Write(stream, MemoryUtil.GetLeU4(signature.ExpectedCrc));

    //Fill ImageDirectoryEntrySecurity
    stream.Seek(peFile.SecurityDataDirectoryRange.Position, SeekOrigin.Begin);
    Write(stream, MemoryUtil.GetLeU4(signature.SignatureBlobOffset));
    Write(stream, MemoryUtil.GetLeU4(signature.SignatureBlobSize));

    //Write signature to the end of the file
    stream.Seek(signature.SignatureBlobOffset, SeekOrigin.Begin);

    Write(stream, MemoryUtil.GetLeU4(signature.SignatureBlobSize));
    Write(stream, MemoryUtil.GetLeU2(signature.CertificateRevision));
    Write(stream, MemoryUtil.GetLeU2(signature.CertificateType));
    Write(stream, signature.SignatureBlob);

    stream.SetLength(stream.Position);
  }

  private static void Write(Stream stream, uint value) => Write(stream, BitConverter.GetBytes(value));
  private static void Write(Stream stream, ushort value) => Write(stream, BitConverter.GetBytes(value));

  private static void Write(Stream stream, byte[] buffer)
  {
    stream.Write(buffer, 0, buffer.Length);
  }
}