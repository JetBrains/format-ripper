package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.DataInfo
import com.jetbrains.signatureverifier.DataValue
import com.jetbrains.util.Rewind
import com.jetbrains.util.Seek
import com.jetbrains.util.SeekOrigin
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel

/**
 * Contains all information required to insert extracted signature back to file
 */
@Serializable
data class PeFileMetaInfo(
  var checkSum: DataValue = DataValue(),
  var securityRva: DataValue = DataValue(),
  var securitySize: DataValue = DataValue(),
  var dwLength: DataValue = DataValue(),
  var wRevision: DataValue = DataValue(),
  var wCertificateType: DataValue = DataValue(),
  var signaturePosition: DataInfo = DataInfo(0, 0)
) : FileMetaInfo {
  override fun modifyFile(stream: SeekableByteChannel, signature: ByteArray) {
    listOf(
      checkSum,
      securityRva,
      securitySize,
      dwLength,
      wRevision,
      wCertificateType,
    ).forEach {
      stream.Seek(it.dataInfo.Offset.toLong(), SeekOrigin.Begin)
      stream.write(ByteBuffer.wrap(it.value))
    }

    stream.Seek(signaturePosition.Offset.toLong(), SeekOrigin.Begin)
    stream.write(ByteBuffer.wrap(signature))
    val alignment = (8 - stream.position() % 8) % 8
    stream.write(ByteBuffer.wrap(ByteArray(alignment.toInt())))

    stream.Rewind()
    stream.close()
  }
}