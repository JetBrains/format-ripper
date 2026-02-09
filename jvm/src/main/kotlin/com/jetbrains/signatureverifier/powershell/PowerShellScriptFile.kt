package com.jetbrains.signatureverifier.powershell

import com.jetbrains.signatureverifier.SignatureData
import com.jetbrains.signatureverifier.bouncycastle.cms.CMSSignedData
import com.jetbrains.signatureverifier.crypt.OIDs.SPC_INDIRECT_DATA
import com.jetbrains.signatureverifier.crypt.OIDs.SPC_SIPINFO_OBJID
import com.jetbrains.signatureverifier.crypt.VerifySignatureResult
import com.jetbrains.signatureverifier.crypt.VerifySignatureStatus
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x509.DigestInfo
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSTypedData
import org.jetbrains.annotations.NotNull
import java.io.InputStream
import java.nio.channels.Channels
import java.nio.channels.SeekableByteChannel
import java.security.MessageDigest


open class PowerShellScriptFile {
  private val script: PowerShellScript

  constructor(@NotNull channel: SeekableByteChannel) {
    script = PowerShellScript(Channels.newInputStream(channel))
  }

  constructor(@NotNull stream: InputStream) {
    script = PowerShellScript(stream)
  }

  fun GetSignatureData(): SignatureData {
    val bytes = script.decodeSignatureBlock() ?: return SignatureData.Empty

    return SignatureData(null, bytes)
  }

  /**
   * Computes hash of the content, without signature.
   * Useful to verify that hash stored in signature is the same as content hash.
   */
  fun ComputeHash(@NotNull algName: String): ByteArray {
    val digest = MessageDigest.getInstance(algName)
    return script.computeDigest(digest)
  }

  fun GetContentWithoutSignature(): String {
    return script.contentWithoutSignatureBlock
  }

  companion object {
    private fun invalid(message: String): VerifySignatureResult {
      return VerifySignatureResult(VerifySignatureStatus.InvalidSignature, message)
    }
  }

  /**
   * Returns [VerifySignatureResult] with either [com.jetbrains.signatureverifier.crypt.VerifySignatureStatus.Valid] or [com.jetbrains.signatureverifier.crypt.VerifySignatureStatus.InvalidSignature]
   */
  fun VerifyContentHash(
    signedData: CMSSignedData,
    file: PowerShellScriptFile
  ): VerifySignatureResult {
    try {
      if (signedData.digestAlgorithmIDs.size != 1) {
        return invalid("Signed Data must contain exactly one DigestAlgorithm, got: ${signedData.digestAlgorithmIDs}")
      }

      val signedDataAlgorithm = signedData.digestAlgorithmIDs.first().algorithm

      val digestInfo: DigestInfo = signedData.signedContent?.let { getSpcIndirectDataContent(it) }
        ?: return invalid("Signed Data does not contain SpcIndirectData structure ($SPC_INDIRECT_DATA) with DigestInfo")

      // Check that SpcIndirectContent DigestAlgorithm equals CMSSignedData algorithm
      if (digestInfo.algorithmId.algorithm != signedDataAlgorithm) {
        return invalid("Signed Data algorithm does not match with spcDigestAlgorithm")
      }

      // Check that SignerInfo DigestAlgorithm equals CMSSignedData algorithm
      if (signedData.signerInfos.size() != 1) {
        return invalid("Signed Data must contain exactly one SignerInfo. Got: ${signedData.signerInfos.toList()}")
      }

      val signerInformation = signedData.signerInfos.first()
      if (signerInformation.digestAlgorithmID.algorithm != signedDataAlgorithm) {
        return invalid("Signed Data algorithm doesn't match with SignerInformation algorithm")
      }

      // Check the embedded hash in spcIndirectContent matches with the computed hash of the pefile
      if (!file.ComputeHash(signedDataAlgorithm.id).contentEquals(digestInfo.digest)) {
        return invalid("The embedded hash in the SignedData is not equal to the computed hash of file content")
      }

      return VerifySignatureResult(VerifySignatureStatus.Valid)
    } catch (e: CMSException) {
      return invalid("Error verifying signature: ${e.message}")
    }
  }

  // See SpcIndirectDataToken.cs
  private fun getSpcIndirectDataContent(contentInfo: CMSTypedData): DigestInfo? {
    if (SPC_INDIRECT_DATA != contentInfo.contentType) {
      return null
    }
    val obj = contentInfo.content as? ASN1Sequence ?: return null
    val sequences = obj.objects.toList().filterIsInstance<ASN1Sequence>()
    if (sequences.size != 2) {
      throw CMSException("Incorrect SpcIndirectData structure: must be a sequence of two nested sequences, got: ${sequences.size}")
    }
    if (SPC_SIPINFO_OBJID != sequences[0].objects.nextElement()) {
      throw CMSException("Incorrect SpcIndirectData structure: first nested sequence must contain SPC_SIPINFO_OBJID, got: ${sequences[0].objects.nextElement()}")
    }
    return DigestInfo.getInstance(sequences[1])
  }
}


