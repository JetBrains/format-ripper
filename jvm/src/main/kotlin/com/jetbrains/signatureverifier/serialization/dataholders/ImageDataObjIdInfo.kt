package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import com.jetbrains.signatureverifier.serialization.toPrimitiveList
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject

@Serializable
data class ImageDataObjIdInfo(
  val identifier: TextualInfo,
  val hexCode: TextualInfo,
  val content: EncodableInfo
) : EncodableInfo {
  companion object {
    fun getInstance(sequence: DLSequence): ImageDataObjIdInfo {
      val id = TextualInfo.getInstance(sequence.first())
      val seq = sequence.last() as DLSequence

      val iterator = seq.iterator()

      val hexCode = TextualInfo.getInstance(iterator.next())

      val content = when (val next = iterator.next()) {
        // PE
        is DLTaggedObject -> {
          val taggedObject = seq.last() as DLTaggedObject
          val secondLevelTaggedObject = taggedObject.baseObject as DLTaggedObject
          val thirdLevelObject = secondLevelTaggedObject.baseObject.let { obj ->
            when (obj) {
              is DLTaggedObject -> TaggedObjectInfo(
                obj.isExplicit,
                obj.tagNo,
                TextualInfo.getInstance(obj.baseObject)
              )

              is DLSequence -> SequenceInfo(obj.map {
                TextualInfo.getInstance(
                  it
                )
              })

              else -> throw IllegalArgumentException("Unexpected object type ${obj.javaClass}")
            }
          }

          TaggedObjectInfo(
            taggedObject.isExplicit,
            taggedObject.tagNo,
            TaggedObjectInfo(
              secondLevelTaggedObject.isExplicit,
              secondLevelTaggedObject.tagNo,
              thirdLevelObject
            )
          )
        }

        else -> {
          val list = mutableListOf(TextualInfo.getInstance(next))
          while (iterator.hasNext()) {
            list.add(TextualInfo.getInstance(iterator.next()))
          }
          SequenceInfo(list)
        }
      }


      return ImageDataObjIdInfo(id, hexCode, content)
    }
  }

  override fun toPrimitive(): ASN1Primitive =
    listOf(
      identifier.toPrimitive(),
      (if (content is SequenceInfo)
        (mutableListOf(hexCode.toPrimitive()) + content.content.toPrimitiveList()).toDLSequence()
      else
        listOf(
          hexCode.toPrimitive(),
          content.toPrimitive()
        ).toDLSequence()
        )
    ).toDLSequence()

}