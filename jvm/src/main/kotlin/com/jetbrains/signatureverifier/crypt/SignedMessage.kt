package com.jetbrains.signatureverifier.crypt

import com.jetbrains.signatureverifier.SignatureData
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cms.CMSProcessableByteArray
import org.jetbrains.annotations.NotNull
import java.io.IOException

class SignedMessage {
  companion object {
    fun CreateInstance(signatureData: SignatureData): SignedMessage {
      if (signatureData.IsEmpty)
        error("signatureData is empty")

      if (signatureData.HasAttachedSignedData)
        return SignedMessage(signatureData.SignedData!!, signatureData.CmsData!!)
      return SignedMessage(signatureData.CmsData!!)
    }
  }

  val SignedData: CMSSignedData

  private constructor (@NotNull pkcs7Data: ByteArray) {
    val asnStream = ASN1InputStream(pkcs7Data)
    val pkcs7 = ContentInfo.getInstance(asnStream.readObject())
    SignedData = CMSSignedData(pkcs7)
  }

  private constructor(@NotNull signedData: ByteArray, @NotNull pkcs7Data: ByteArray) {
    val signedContent = CMSProcessableByteArray(signedData)

    try {
      val asnStream = ASN1InputStream(pkcs7Data)
      val pkcs7 = ContentInfo.getInstance(asnStream.readObject())
      SignedData = CMSSignedData(signedContent, pkcs7)
    } catch (ex: IOException) {
      throw Exception("Invalid signature format", ex)
    }
  }

  internal constructor(@NotNull obj: ASN1Object) {
    val pkcs7 = ContentInfo.getInstance(obj)
    SignedData = CMSSignedData(pkcs7)
  }
}
