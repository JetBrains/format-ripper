using System;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.Pe.Impl;

namespace JetBrains.FormatRipper.Pe;

public class PeSignatureInjector
{
  public static unsafe void InjectSignature(Stream stream, PeFileSignature signature)
  {
    if (!stream.CanWrite) throw new ArgumentException("Provided file stream is not writeable");
    if (signature.SignatureBlob.Length + sizeof(WIN_CERTIFICATE) != signature.SignatureBlobSize)
      throw new ArgumentException($"Signature blob actual length ({signature.SignatureBlob.Length} bytes + {sizeof(WIN_CERTIFICATE)} bytes for the WIN_CERTIFICATE structure) doesn't match the value from IMAGE_DATA_DIRECTORY structure {signature.SignatureBlobSize}");

    if (stream.Length != signature.SignatureBlobOffset)
      throw new SignatureInjectionException($"Target file size (${stream.Length} bytes) doesn't match the desired signature start offset (${signature.SignatureBlobOffset} bytes).");

    var peFile = PeFile.Parse(stream);

    //Write new PE file checksum
    stream.Seek(peFile.ChecksumRange.Position, SeekOrigin.Begin);
    Write(stream, MemoryUtil.GetLeU4(signature.ExpectedCrc));

    //Fill ImageDirectoryEntrySecurity
    stream.Seek(peFile.SecurityDataDirectoryRange.Position, SeekOrigin.Begin);
    Write(stream, MemoryUtil.GetLeU4(signature.SignatureBlobOffset));
    Write(stream, MemoryUtil.GetLeU4(signature.SignatureBlobSize));

    //Write signature to the end of the file
    stream.Seek(0, SeekOrigin.End);
    Write(stream, MemoryUtil.GetLeU4(signature.SignatureBlobSize));
    Write(stream, MemoryUtil.GetLeU2(signature.CertificateRevision));
    Write(stream, MemoryUtil.GetLeU2(signature.CertificateType));
    Write(stream, signature.SignatureBlob);
  }

  private static void Write(Stream stream, uint value) => Write(stream, BitConverter.GetBytes(value));
  private static void Write(Stream stream, ushort value) => Write(stream, BitConverter.GetBytes(value));

  private static void Write(Stream stream, byte[] buffer)
  {
    stream.Write(buffer, 0, buffer.Length);
  }
}