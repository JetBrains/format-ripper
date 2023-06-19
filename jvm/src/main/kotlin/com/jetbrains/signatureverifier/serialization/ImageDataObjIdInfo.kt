package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject

@Serializable
data class ImageDataObjIdInfo(
  val identifier: StringInfo,
  val hexCode: StringInfo,
  val content: TaggedObjectInfo
) : EncodableInfo {
  companion object {
    fun getInstance(sequence: DLSequence): ImageDataObjIdInfo {
      val id = StringInfo.getInstance(sequence.first())
      val seq = sequence.last() as DLSequence
      val hexCode = StringInfo.getInstance(seq.first())

      val taggedObject = seq.last() as DLTaggedObject
      val secondLevelTaggedObject = taggedObject.baseObject as DLTaggedObject
      val thirdLevelObject = when (secondLevelTaggedObject.baseObject) {
        is DLTaggedObject -> TaggedObjectInfo(
          TaggedObjectMetaInfo(secondLevelTaggedObject.baseObject as DLTaggedObject),
          StringInfo.getInstance((secondLevelTaggedObject.baseObject as DLTaggedObject).baseObject)
        )

        else -> SequenceInfo((secondLevelTaggedObject.baseObject as DLSequence).map {
          StringInfo.getInstance(
            it
          )
        })
      }

      val content = TaggedObjectInfo(
        TaggedObjectMetaInfo(taggedObject),
        TaggedObjectInfo(
          TaggedObjectMetaInfo(secondLevelTaggedObject),
          thirdLevelObject
        )
      )
      return ImageDataObjIdInfo(id, hexCode, content)
    }
  }

  override fun toPrimitive(): ASN1Primitive =
    listOf(
      identifier.toPrimitive(),
      listOf(
        hexCode.toPrimitive(),
        content.toPrimitive()
      ).toDLSequence()
    ).toDLSequence()

}