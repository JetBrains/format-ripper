package com.jetbrains.signatureverifier.powershell

import org.apache.commons.io.ByteOrderMark
import org.apache.commons.io.input.BOMInputStream
import java.io.BufferedInputStream
import java.io.InputStream
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.*
import java.util.regex.Pattern

/**
 * Based on https://github.com/ebourg/jsign/blob/master/jsign-core/src/main/java/net/jsign/script/PowerShellScript.java
 */
class PowerShellScript(input: InputStream, encoding: Charset = StandardCharsets.UTF_8) {

  companion object {
    const val SIGNATURE_START: String = "# SIG # Begin signature block"
    const val SIGNATURE_END: String = "# SIG # End signature block"

    private const val EOL = "\\r\\n"
    private const val EOL_OPTIONAL_CR = "\\r?\\n"

    private val SupportedBOMs: Array<ByteOrderMark> =
      arrayOf(ByteOrderMark.UTF_8, ByteOrderMark.UTF_16BE, ByteOrderMark.UTF_16LE)

    private val SignatureBlockPattern: Pattern = Pattern.compile(
      "(?s)" +
        EOL +
        SIGNATURE_START + EOL +
        "(?<signature>.*)" +
        SIGNATURE_END + EOL
    )
    private val SignatureBlockRemovalPattern: Pattern = Pattern.compile(
      "(?s)" +
        EOL_OPTIONAL_CR +
        SIGNATURE_START + EOL_OPTIONAL_CR +
        ".*" +
        SIGNATURE_END + EOL_OPTIONAL_CR
    )
  }

  val content: String

  init {
    var encoding = encoding

    BOMInputStream
      .builder()
      .setInputStream(BufferedInputStream(input))
      .setInclude(true)
      .setByteOrderMarks(*SupportedBOMs)
      .get()
      .use { stream ->
        stream.getBOMCharsetName()?.let {
          encoding = Charset.forName(it)
        }
        content = String(stream.readBytes(), encoding)
      }
  }

  fun decodeSignatureBlock(): ByteArray? {
    val cleanedSignature = (signatureBlock ?: return null).replace("# ", "").replace("\r", "").replace("\n", "")
    return Base64.getDecoder().decode(cleanedSignature)
  }

  private val signatureBlock: String?
    get() {
      val matcher = SignatureBlockPattern.matcher(content)
      if (!matcher.find()) {
        return null
      }

      return matcher.group("signature")
    }

  val contentWithoutSignatureBlock: String
    get() = SignatureBlockRemovalPattern.matcher(content).replaceFirst("")

  fun computeDigest(digest: MessageDigest): ByteArray {
    digest.update(contentWithoutSignatureBlock.toByteArray(StandardCharsets.UTF_16LE))
    return digest.digest()
  }
}