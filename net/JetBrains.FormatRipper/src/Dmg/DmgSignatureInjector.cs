using System;
using System.IO;
using JetBrains.FormatRipper.Dmg.Impl;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Dmg;

public class DmgSignatureInjector
{
  public static unsafe void InjectSignature(Stream sourceStream, Stream outputStream, DmgFileSignature signature)
  {
    sourceStream.Seek(-sizeof(UDIF), SeekOrigin.End);

    UDIF udif;
    StreamUtil.ReadBytes(sourceStream, (byte*)&udif, sizeof(UDIF));

    sourceStream.Seek(0, SeekOrigin.Begin);

    long existingSignatureOffset = checked((long)MemoryUtil.GetBeU8(udif.CodeSignatureOffset));
    long existingSignatureLength = checked((long)MemoryUtil.GetBeU8(udif.CodeSignatureLength));

    long usefullPayloadLength = existingSignatureLength == 0 ? sourceStream.Length - sizeof(UDIF) : existingSignatureOffset;

    if (usefullPayloadLength > signature.SignatureOffset)
      throw new SignatureInjectionException($"Cannot transfer the signature. Expected file size: {signature.SignatureOffset + sizeof(UDIF)} bytes, bug got {sourceStream.Length} bytes");

    long bytesToCopy = Math.Min(usefullPayloadLength, signature.SignatureOffset);

    StreamUtil.CopyBytes(sourceStream, outputStream, bytesToCopy);

    if (bytesToCopy < signature.SignatureOffset)
    {
      long paddingBytes = signature.SignatureOffset - bytesToCopy;
      byte[] padding = new byte[paddingBytes];
      outputStream.Write(padding, 0, padding.Length);
    }

    outputStream.Write(signature.SignatureBlob, 0, signature.SignatureBlob.Length);
    udif.CodeSignatureLength = MemoryUtil.GetBeU8((ulong)signature.SignatureLength);
    udif.CodeSignatureOffset = MemoryUtil.GetBeU8((ulong)signature.SignatureOffset);

    StreamUtil.WriteBytes(outputStream, (byte*)&udif, sizeof(UDIF));
  }
}