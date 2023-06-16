package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.crypt.SignedMessageVerifier
import com.jetbrains.signatureverifier.serialization.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.SignerInfo
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.*
import java.util.stream.Stream
import com.jetbrains.signatureverifier.serialization.SignerInfo as SerializableSignerInfo

class SignerInformationSerializationTests {

  /**
   * Tests, that we can recreate `authenticatedAttributes` field of `SignerInfo` from serialized data
   */
  @ParameterizedTest
  @MethodSource("SignedPEProvider")
  fun SignedAttributesSetializaionTest(signedPeResourceName: String) {
    getTestByteChannel("pe", signedPeResourceName).use {
      val peFile = PeFile(it)
      val signatureData = peFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)

      val signedData = signedMessage.SignedData
      val signers = signedData.signerInfos.signers
      signers.forEach { signer ->
        val primitive = signer.toASN1Structure()
        val order = primitive.authenticatedAttributes.map {
          (it as DLSequence).first()
        }

        val attributeInfos = order.map {
          AttributeInfo.getInstance(
            signer.signedAttributes?.get(it as ASN1ObjectIdentifier) as Attribute
          )
        }

        val recreatedSet = listToDLSet(attributeInfos.map { attr ->
          attr.toPrimitive()
        })

        Assertions.assertEquals(
          true,
          compareBytes(
            primitive.authenticatedAttributes.getEncoded("DER"),
            recreatedSet.getEncoded("DER"),
            verbose = false
          )
        )
      }
    }
  }

  /**
   * Tests, that we can recreate `sid` field of `SignerInfo` from serialized data
   */
  @ParameterizedTest
  @MethodSource("SignedPEProvider")
  fun SignerIdSetializaionTest(signedPeResourceName: String) {
    getTestByteChannel("pe", signedPeResourceName).use {
      val peFile = PeFile(it)
      val signatureData = peFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)

      val signedData = signedMessage.SignedData
      val signers = signedData.signerInfos.signers
      signers.forEach { signer ->
        val primitive = signer.toASN1Structure()
        val signerIdentifierInfo = SignerIdentifierInfo(signer.sID)

        Assertions.assertEquals(
          true,
          compareBytes(
            signerIdentifierInfo.toPrimitive().getEncoded("DER"),
            primitive.sid.getEncoded("DER"),
            verbose = false
          )
        )
      }
    }
  }

  @ParameterizedTest
  @MethodSource("SignedPEProvider")
  fun SignersSetializaionTest(signedPeResourceName: String) {
    getTestByteChannel("pe", signedPeResourceName).use {
      val verificationParams = SignatureVerificationParams(null, null, false, false)
      val peFile = PeFile(it)
      val signatureData = peFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)
      runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams) }

      val signedData = signedMessage.SignedData
      val signers = signedData.signerInfos.signers
      signers.forEach { signer ->
        val primitive = signer.toASN1Structure()
        val signerInfo = SerializableSignerInfo(signer)

        val json = Json.encodeToString(signerInfo)

        val recreatedSignerInfo =
          SignerInfo.getInstance(Json.decodeFromString<SerializableSignerInfo>(json).toPrimitive())

        Assertions.assertEquals(
          true,
          compareBytes(
            primitive.getEncoded("DER"),
            recreatedSignerInfo.getEncoded("DER"),
            verbose = false
          )
        )
      }

      val signerInfos = signers.map { SerializableSignerInfo(it) }
      val json = Json.encodeToString(signerInfos)


      val recreatedSignerInfos =
        listToDLSet(
          Json.decodeFromString<List<SerializableSignerInfo>>(json).map { it.toPrimitive() })

      Assertions.assertEquals(
        true,
        compareBytes(
          signedData.signedData.signerInfos.getEncoded("DER"),
          recreatedSignerInfos.getEncoded("DER"),
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
    fun SignedPEProvider(): Stream<Arguments> {
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