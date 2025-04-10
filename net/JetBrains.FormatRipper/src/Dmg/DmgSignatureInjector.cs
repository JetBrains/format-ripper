using System;
using System.IO;
using JetBrains.FormatRipper.Dmg.Impl;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Dmg;

public class DmgSignatureInjector
{
  /// <summary>
  /// Inject signature into a DMG file
  /// </summary>
  /// <param name="sourceStream">Read-only stream of a file into which you want to inject a signature</param>
  /// <param name="outputStream">Stream for writing a result file with an injected signature</param>
  /// <param name="signatureTransferData">Signature transfer data to inject</param>
  /// <exception cref="ArgumentException">Thrown if output stream is not writeable</exception>
  /// <exception cref="FormatException">Thrown if input file has invalid format</exception>
  /// <exception cref="SignatureInjectionException">Thrown on signature transfer error. This usually happens when trying to transfer signatures between incompatible files.</exception>
  public static unsafe void InjectSignature(Stream sourceStream, Stream outputStream, IDmgSignatureTransferData signatureTransferData)
  {
    sourceStream.Seek(-sizeof(UDIF), SeekOrigin.End);

    UDIF udif;
    StreamUtil.ReadBytes(sourceStream, (byte*)&udif, sizeof(UDIF));

    if ((DmgMagic)MemoryUtil.GetBeU4(udif.Magic) != DmgMagic.KOLY)
      throw new FormatException("Invalid DMG file UDIF structure magic");

    sourceStream.Seek(0, SeekOrigin.Begin);

    long existingSignatureOffset = checked((long)MemoryUtil.GetBeU8(udif.CodeSignatureOffset));
    long existingSignatureLength = checked((long)MemoryUtil.GetBeU8(udif.CodeSignatureLength));

    long usefullPayloadLength = existingSignatureLength == 0 ? sourceStream.Length - sizeof(UDIF) : existingSignatureOffset;

    if (usefullPayloadLength != signatureTransferData.SignatureOffset)
      throw new SignatureInjectionException($"Cannot transfer the signature. Expected file size: {signatureTransferData.SignatureOffset + sizeof(UDIF)} bytes, but got {sourceStream.Length} bytes");

    long bytesToCopy = Math.Min(usefullPayloadLength, signatureTransferData.SignatureOffset);

    StreamUtil.CopyBytes(sourceStream, outputStream, bytesToCopy);

    outputStream.Write(signatureTransferData.SignatureBlob, 0, signatureTransferData.SignatureBlob.Length);
    udif.CodeSignatureLength = MemoryUtil.GetBeU8((ulong)signatureTransferData.SignatureLength);
    udif.CodeSignatureOffset = MemoryUtil.GetBeU8((ulong)signatureTransferData.SignatureOffset);

    StreamUtil.WriteBytes(outputStream, (byte*)&udif, sizeof(UDIF));
  }
}