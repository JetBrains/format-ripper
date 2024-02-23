using System;
using System.IO;
using JetBrains.FormatRipper.Dmg.Impl;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Dmg;

public class DmgSignatureInjector
{
  public static unsafe void InjectSignature(Stream sourceStream, Stream outputStream, DmgSignatureTransferData signatureTransferData)
  {
    sourceStream.Seek(-sizeof(UDIF), SeekOrigin.End);

    UDIF udif;
    StreamUtil.ReadBytes(sourceStream, (byte*)&udif, sizeof(UDIF));

    sourceStream.Seek(0, SeekOrigin.Begin);

    long existingSignatureOffset = checked((long)MemoryUtil.GetBeU8(udif.CodeSignatureOffset));
    long existingSignatureLength = checked((long)MemoryUtil.GetBeU8(udif.CodeSignatureLength));

    long usefullPayloadLength = existingSignatureLength == 0 ? sourceStream.Length - sizeof(UDIF) : existingSignatureOffset;

    if (usefullPayloadLength != signatureTransferData.SignatureOffset)
      throw new SignatureInjectionException($"Cannot transfer the signature. Expected file size: {signatureTransferData.SignatureOffset + sizeof(UDIF)} bytes, bug got {sourceStream.Length} bytes");

    long bytesToCopy = Math.Min(usefullPayloadLength, signatureTransferData.SignatureOffset);

    StreamUtil.CopyBytes(sourceStream, outputStream, bytesToCopy);

    outputStream.Write(signatureTransferData.SignatureBlob, 0, signatureTransferData.SignatureBlob.Length);
    udif.CodeSignatureLength = MemoryUtil.GetBeU8((ulong)signatureTransferData.SignatureLength);
    udif.CodeSignatureOffset = MemoryUtil.GetBeU8((ulong)signatureTransferData.SignatureOffset);

    StreamUtil.WriteBytes(outputStream, (byte*)&udif, sizeof(UDIF));
  }
}