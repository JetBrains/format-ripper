package com.jetbrains.signatureverifier.dmg

import com.jetbrains.signatureverifier.SignatureData
import com.jetbrains.signatureverifier.macho.CSMAGIC
import com.jetbrains.signatureverifier.macho.MachoConsts
import com.jetbrains.signatureverifier.macho.MachoUtils
import com.jetbrains.util.*
import org.jetbrains.annotations.NotNull
import java.nio.channels.SeekableByteChannel

class DmgFile {
  val UDIFResourceFileSize = 512
  val numDataChecksumOffset = 84L
  private val stream: SeekableByteChannel
  private var signedData: ByteArray? = null
  private var cmsData: ByteArray? = null

  constructor(@NotNull stream: SeekableByteChannel) {
    this.stream = stream
    val reader = BinaryReader(stream.Rewind())

    stream.Jump(stream.size() - UDIFResourceFileSize)
    if (reader.ReadUInt32Be() != 0x6b6f6c79u) // 'koly' signature
      error("Could not identify UDIFResourceFile")

    stream.Seek(numDataChecksumOffset - 4, SeekOrigin.Current)
    val numDataChecksum = reader.ReadUInt32Be().toInt()

    // skip to reserved
    stream.Seek(numDataChecksum * 4L + 16, SeekOrigin.Current)
    stream.Seek(64, SeekOrigin.Current)

    val codeSignaturePointer = CodeSignaturePointer(
      reader.ReadUInt64Be().toLong(),
      reader.ReadUInt64Be().toLong()
    )

    stream.Jump(codeSignaturePointer.offset)
    val superBlobStart = stream.position()

    val codeSignatureMagic = reader.ReadUInt32Be()
    if (codeSignatureMagic != MachoConsts.CSMAGIC_SIGNATURE_DATA)
      error("Could not read Code Signature block")

    val codeSignatureLength = reader.ReadUInt32Be()
    val numBlobs = reader.ReadUInt32Be().toInt()

    repeat(numBlobs) {
      val blobIndexType = reader.ReadUInt32Be()
      val blobIndexOffset = reader.ReadUInt32Be()
      val position = stream.position()
      when (blobIndexType.toLong()) {
        MachoConsts.CSSLOT_CODEDIRECTORY -> {
          stream.Seek(superBlobStart, SeekOrigin.Begin)
          stream.Seek(blobIndexOffset.toLong(), SeekOrigin.Current)
          val (blobMagic, data) = MachoUtils.ReadCodeDirectoryBlob(reader)
          signedData = data
          stream.Seek(position, SeekOrigin.Begin)
        }

        else -> {
          val magicEnum = CSMAGIC.getInstance(blobIndexType)

          stream.Seek(superBlobStart, SeekOrigin.Begin)
          stream.Seek(blobIndexOffset.toLong(), SeekOrigin.Current)
          val (blobMagic, data) = MachoUtils.ReadBlob(reader)
          stream.Seek(position, SeekOrigin.Begin)
          if (magicEnum == CSMAGIC.CMS_SIGNATURE) {
            cmsData = data
          }
        }
      }
    }
  }

  fun GetSignatureData(): SignatureData = SignatureData(signedData, cmsData)


  /**
   * NOTE
   * This class is made under the assumption, that `reserved` block in UDIFResourceFile has a structure of
   * ```
   * 64 bytes of some info;
   * ReservedSectorItem;
   * 40 bytes of some info;
   * ```
   * which gives a total size of 120.
   *
   * Be aware, that it might be wrong.
   *
   * The structure of `ReservedSectorItem` itself was deduced from the sample files and might also be inaccurate
   */
  data class CodeSignaturePointer(
    val offset: Long,
    val length: Long
  )
}

