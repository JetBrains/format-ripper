package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.cf.MsiFile
import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.macho.MachoArch
import com.jetbrains.signatureverifier.serialization.dataholders.AttributeInfo
import com.jetbrains.signatureverifier.serialization.compareBytes
import com.jetbrains.signatureverifier.serialization.fileInfos.getTestByteChannel
import com.jetbrains.signatureverifier.serialization.toDLSet
import com.jetbrains.util.TestUtil
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.stream.Stream

class AttributesSerializationTests {
  /**
   * Tests, that we can recreate `authenticatedAttributes` field of `SignerInfo` from serialized data
   */
  @ParameterizedTest
  @MethodSource("SignedPEProvider")
  fun PE_Test(signedPeResourceName: String) {
    getTestByteChannel("pe", signedPeResourceName).use {
      val peFile = PeFile(it)
      val signatureData = peFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)

      SignedAttributesSerializaionTest(signedMessage)
    }
  }

  @ParameterizedTest
  @MethodSource("SignedMachoProvider")
  fun Macho_Test(signedResourceName: String) {
    val machoFiles =
      Files.newByteChannel(
        TestUtil.getTestDataFile(
          "mach-o",
          signedResourceName
        ), StandardOpenOption.READ
      ).use {
        MachoArch(it).Extract()
      }

    for (machoFile in machoFiles) {
      val signatureData = machoFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      SignedAttributesSerializaionTest(signedMessage)
    }
  }

  @ParameterizedTest
  @MethodSource("SignedMsiProvider")
  fun Msi_Test(signedResourceName: String) {
    val result = TestUtil.getTestByteChannel("msi", signedResourceName).use {
      val verificationParams = SignatureVerificationParams(null, null, false, false)
      val msiFile = MsiFile(it)
      val signatureData = msiFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      SignedAttributesSerializaionTest(signedMessage)
    }
  }

  fun SignedAttributesSerializaionTest(signedMessage: SignedMessage) {
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

      val recreatedSet = attributeInfos.map { attr ->
        attr.toPrimitive()
      }.toDLSet()

      Assertions.assertEquals(
        true,
        compareBytes(
          primitive.authenticatedAttributes.getEncoded("DER"),
          recreatedSet.getEncoded("DER"),
          verbose = false
        )
      )

      if (primitive.unauthenticatedAttributes != null) {
        val unsignedAttributeInfos = primitive.unauthenticatedAttributes.map {
          (it as DLSequence).first()
        }.map {
          AttributeInfo.getInstance(
            signer.unsignedAttributes?.get(it as ASN1ObjectIdentifier) as Attribute
          )
        }
        val json = Json.encodeToString(unsignedAttributeInfos)
        val recreatedUnsignedSet = unsignedAttributeInfos.map { attr ->
          attr.toPrimitive()
        }.toDLSet()

        Assertions.assertEquals(
          true,
          compareBytes(
            primitive.unauthenticatedAttributes.getEncoded("DER"),
            recreatedUnsignedSet.getEncoded("DER"),
            verbose = true
          )
        )
      }
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
    fun SignedMsiProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("2dac4b.msi"),
        Arguments.of("firefox.msi"),
        Arguments.of("sumatra.msi"),
      )
    }

    @JvmStatic
    fun SignedMachoProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("env-wrapper.x64"),
        Arguments.of("libMonoSupportW.x64.dylib"),
        Arguments.of("cat"),
        Arguments.of("JetBrains.Profiler.PdbServer"),
        Arguments.of("fat.dylib_signed"),
        Arguments.of("libhostfxr.dylib")
      )
    }

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