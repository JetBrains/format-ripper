package com.jetbrains.signatureverifier.tests.serialization

import TaggedObjectMetaInfo
import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.serialization.*
import org.bouncycastle.asn1.ASN1Null
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.util.CollectionStore
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.*
import java.util.stream.Stream

class SignatureRecreationTests {

  /**
   * Tests, that we can recreate `certificates` field of `SignedData` from serialized data
   */
  @ParameterizedTest
  @MethodSource("RecreateSignatureTestProvider")
  fun RecreateSignatureTest(signedPeResourceName: String) {
    getTestByteChannel("pe", signedPeResourceName).use {
      val peFile = PeFile(it)
      val signatureData = peFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)

      val signedData = signedMessage.SignedData
      val innerSignedData = signedData.signedData

      val contentInfo = signedData.contentInfo

      // Digest Algorithms
      val serializedDigestAlgorithms = DigestAlgorithmsInfo.getInstance(signedData.digestAlgorithmIDs)
      val deserializedDigestAlgorithms = serializedDigestAlgorithms.toPrimitive()

      Assertions.assertEquals(
        true,
        compareBytes(
          innerSignedData.digestAlgorithms.getEncoded("DER"),
          deserializedDigestAlgorithms.getEncoded("DER"), verbose = false
        )
      )

      // Certificates
      val beautifiedCertificates = signedData.certificates
      val certificateInfos =
        beautifiedCertificates.getMatches(null).toList().map { CertificateInfo.getInstance(it) }

      val recreatedHolders = certificateInfos.map { it.toX509CertificateHolder() }
      val recreatedStore = CollectionStore(recreatedHolders)
      val recreatedCertificates = recreateCertificatesFromStore(recreatedStore)

      Assertions.assertEquals(
        true,
        compareBytes(
          recreatedCertificates.getEncoded("DER"),
          innerSignedData.certificates.getEncoded("DER"),
          verbose = false
        )
      )

      val originalSignerInfos = innerSignedData.signerInfos
      val recreatedSignerInfos =
        recreateSignerInfosFromSignerInformationStore(signedData.signerInfos)
      Assertions.assertEquals(
        true,
        compareBytes(
          originalSignerInfos.getEncoded("DER"),
          recreatedSignerInfos.getEncoded("DER"),
          verbose = false
        )
      )

      val version = innerSignedData.version

      val signedDataSequence = listToDLSequence(
        listOf(
          version,
          deserializedDigestAlgorithms.toASN1Primitive(),
          innerSignedData.encapContentInfo,
          TaggedObjectInfo.getTaggedObjectWithMetaInfo(
            TaggedObjectMetaInfo(0, 2),
            recreatedCertificates.toASN1Primitive()
          ),
          recreatedSignerInfos.toASN1Primitive()
        )
      )

      val copy = SignedData.getInstance(signedDataSequence)

      Assertions.assertEquals(
        true,
        compareBytes(
          innerSignedData.getEncoded("DER"),
          copy.getEncoded("DER"),
          verbose = true
        )
      )

      val recreatedInfo = recreateContentInfoFromSignedData(copy)

      Assertions.assertEquals(
        true,
        compareBytes(
          contentInfo.getEncoded("DER"),
          recreatedInfo.getEncoded("DER"),
          verbose = false
        )
      )

      var originalSignature = peFile.getSignatureMetadata().signature.value
      originalSignature =
        originalSignature.slice(8 until originalSignature.size).toByteArray() // first 8 — metainfo

      val encoded = recreatedInfo.getEncoded("DER")//

      Assertions.assertEquals(
        true,
        compareBytes(
          originalSignature,
          encoded,
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
    fun RecreateSignatureTestProvider(): Stream<Arguments> {
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