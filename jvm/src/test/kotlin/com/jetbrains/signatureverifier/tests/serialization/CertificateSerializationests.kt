package com.jetbrains.signatureverifier.tests.serialization

import com.google.gson.Gson
import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.serialization.*
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.util.CollectionStore
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.*
import java.util.stream.Stream

class CertificateSerializationests {

  /**
   * Tests, that we can recreate `certificates` field of `SignedData` from serialized data
   */
  @ParameterizedTest
  @MethodSource("RecreateCertificatesTestProvider")
  fun RecreateCertificatesTest(signedPeResourceName: String) {
    getTestByteChannel("pe", signedPeResourceName).use {
      val peFile = PeFile(it)
      val signatureData = peFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)

      val signedData = signedMessage.SignedData
      val innerSignedData = signedData.signedData

      val beautifiedCertificates = signedData.certificates.getMatches(null).toList()

      val recreatedList = beautifiedCertificates.map { certificateHolder ->

        val certificateInfo = CertificateInfo.getInstance(certificateHolder)

        val gson = Gson()
        val json = gson.toJson(certificateInfo)
        val certificateInfoFromJson = gson.fromJson(json, certificateInfo::class.java)

        val recreatedCertificateHolder = certificateInfoFromJson.toX509CertificateHolder()

        Assertions.assertEquals(
          true,
          compareBytes(
            recreatedCertificateHolder.encoded,
            certificateHolder.encoded,
            verbose = false
          )
        )
        recreatedCertificateHolder
      }

      val recreatedStore = CollectionStore(recreatedList)
      val recreatedCertificates = recreateCertificatesFromStore(recreatedStore)

      Assertions.assertEquals(
        true,
        compareBytes(
          recreatedCertificates.getEncoded("DER"),
          innerSignedData.certificates.getEncoded("DER"),
          verbose = false
        )
      )
    }
  }

  companion object {
    private const val pe_01_signed = "ServiceModelRegUI.dll"

    private const val pe_02_signed = "self_signed_test.exe"

    private const val pe_03_signed = "shell32.dll"

    private const val pe_04_signed = "IntelAudioService.exe"

    private const val pe_05_signed = "libcrypto-1_1-x64.dll"

    private const val pe_06_signed = "libssl-1_1-x64.dll"

    private const val pe_07_signed = "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe"

    private const val pe_08_signed = "dotnet.exe"
    private const val pe_08_not_signed = "dotnet_no_sign.exe"


    @JvmStatic
    fun RecreateCertificatesTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(
          pe_01_signed
        ),
        Arguments.of(
          pe_02_signed
        ),
        Arguments.of(
          pe_03_signed
        ),
        Arguments.of(
          pe_04_signed
        ),
        Arguments.of(
          pe_05_signed
        ),
        Arguments.of(
          pe_06_signed
        ),
        Arguments.of(
          pe_07_signed
        ),
        Arguments.of(
          pe_08_signed, pe_08_not_signed
        ),
      )
    }
  }

}