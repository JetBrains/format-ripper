package com.jetbrains.signatureverifier.dmg

import com.jetbrains.signatureverifier.SignatureData
import com.jetbrains.signatureverifier.macho.CSMAGIC
import com.jetbrains.signatureverifier.macho.MachoConsts
import com.jetbrains.signatureverifier.macho.MachoUtils
import com.jetbrains.util.*
import org.jetbrains.annotations.NotNull
import java.nio.channels.SeekableByteChannel
import java.security.MessageDigest

class DmgFile(@NotNull stream: SeekableByteChannel) {
  val UDIFResourceFileSize = 512
  private val stream: SeekableByteChannel
  private var signedData: ByteArray? = null
  private var cmsData: ByteArray? = null
  private val codeSignaturePointer: CodeSignaturePointer
  private val codeSignaturePointerOffset = 296L // counted according to the structure described below

  /**
   * Parses UDIFResourceFile, then uses CodeSignatureOffset to extract all signature-related data.
   *
   * UDIFResourceFile structure:
   *  Signature             udifSignature // magic 'koly', 4 bytes
   * 	Version               uint32        // 4 (as of 2013)
   * 	HeaderSize            uint32        // sizeof(this) =  512 (as of 2013)
   * 	Flags                 udifResourceFileFlag // 4 bytes
   * 	RunningDataForkOffset uint64
   * 	DataForkOffset        uint64 // usually 0, beginning of file
   * 	DataForkLength        uint64
   * 	RsrcForkOffset        uint64 // resource fork offset and length
   * 	RsrcForkLength        uint64
   * 	SegmentNumber         uint32 // Usually 1, can be 0
   * 	SegmentCount          uint32 // Usually 1, can be 0
   * 	SegmentID             types.UUID // 128-bit
   *
   * 	DataChecksumType uint32
   * 	DataChecksumSize uint32
   * 	DataChecksum [32]uint32
   *
   * 	PlistOffset uint64 // Offset and length of the blkx plist.
   * 	PlistLength uint64
   *
   * 	Reserved1 [64]byte
   *
   *  -->offset from the beginning of the structure is 296<--
   * 	CodeSignatureOffset uint64
   * 	CodeSignatureLength uint64
   *
   * 	Reserved2 [40]byte
   *
   * 	MasterChecksum UDIFChecksum
   *
   * 	ImageVariant uint32 // Unknown, commonly 1
   * 	SectorCount  uint64
   *
   * 	Reserved3 uint32
   * 	Reserved4 uint32
   * 	Reserved5 uint32
   */
  init {
    this.stream = stream
    val reader = BinaryReader(stream.Rewind())

    val UDIFOffset = stream.size() - UDIFResourceFileSize

    stream.Jump(UDIFOffset)
    if (reader.ReadUInt32Be() != 0x6b6f6c79u) // 'koly' signature
      error("Could not identify UDIFResourceFile")

    stream.Jump(UDIFOffset + codeSignaturePointerOffset)

    codeSignaturePointer = CodeSignaturePointer(
      reader.ReadUInt64Be().toLong(),
      reader.ReadUInt64Be().toLong()
    )

    if (codeSignaturePointer.length > 0) {
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
        when (blobIndexType.toInt()) {
          MachoConsts.CSSLOT_CODEDIRECTORY -> {
            stream.Seek(superBlobStart, SeekOrigin.Begin)
            stream.Seek(blobIndexOffset.toLong(), SeekOrigin.Current)
            signedData = MachoUtils.ReadCodeDirectoryBlob(reader)
            stream.Seek(position, SeekOrigin.Begin)
          }

          MachoConsts.CSSLOT_CMS_SIGNATURE -> {
            stream.Seek(superBlobStart, SeekOrigin.Begin)
            stream.Seek(blobIndexOffset.toLong(), SeekOrigin.Current)
            cmsData = MachoUtils.ReadBlob(reader).let { it.sliceArray(0 until it.size - 2 * UInt.SIZE_BYTES) }
            stream.Seek(position, SeekOrigin.Begin)
          }
        }
      }
    }
  }

  fun GetSignatureData(): SignatureData = SignatureData(signedData, cmsData)

  fun ComputeHash(algName: String): ByteArray {
    val hash = MessageDigest.getInstance(algName)
    val reader = BinaryReader(stream.Rewind())
    // if signature is empty
    if (codeSignaturePointer.length == 0L) {
      hash.update(reader.ReadBytes(stream.size().toInt() - UDIFResourceFileSize)) // exclude UDIF block
    } else {
      // Data before codeSignature
      hash.update(reader.ReadBytes(codeSignaturePointer.offset.toInt()))

      val dataBeforeUDIFLength =
        stream.size() - (codeSignaturePointer.offset + codeSignaturePointer.length) - UDIFResourceFileSize
      // If something is left before UDIF block
      if (dataBeforeUDIFLength > 0) {
        stream.Jump(codeSignaturePointer.offset + codeSignaturePointer.length)
        hash.update(reader.ReadBytes(dataBeforeUDIFLength.toInt()))
      }
    }
    return hash.digest()
  }

  data class CodeSignaturePointer(
    val offset: Long,
    val length: Long
  )
}

