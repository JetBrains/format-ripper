package com.jetbrains.signatureverifier.powershell

import com.jetbrains.signatureverifier.SignableFile
import com.jetbrains.signatureverifier.SignatureData
import org.jetbrains.annotations.NotNull
import java.io.InputStream
import java.nio.channels.Channels
import java.nio.channels.SeekableByteChannel
import java.security.MessageDigest


open class PowershellScriptFile : SignableFile {
  private val script: PowerShellScript

  constructor(@NotNull stream: SeekableByteChannel) {
    script = PowerShellScript(Channels.newInputStream(stream))
  }
  constructor(@NotNull stream: InputStream) {
    script = PowerShellScript(stream)
  }

  override fun GetSignatureData(): SignatureData {
    val bytes = script.decodeSignatureBlock() ?: return SignatureData.Empty

    return SignatureData(null, bytes)
  }

  override fun ComputeHash(@NotNull algName: String): ByteArray {
    val digest = MessageDigest.getInstance(algName)
    return script.computeDigest(digest)
  }

  fun GetContentWithoutSignature(): String {
    return script.contentWithoutSignatureBlock
  }
}


