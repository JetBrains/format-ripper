package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

@Serializable
data class PeEncapContentInfo(
  override val contentType: TextualInfo,
  val imageDataObjIdInfo: ImageDataObjIdInfo,
  val hashAlgorithmInfo: AlgorithmInfo,
  val contentHash: TextualInfo
) : EncapContentInfo() {
    companion object {
        fun getInstance(contentInfo: ContentInfo): PeEncapContentInfo =
            (contentInfo.content as DLSequence).let { contentSequence ->
                (contentSequence.getObjectAt(1) as DLSequence).let { algorithmSequence ->
                    PeEncapContentInfo(
                        TextualInfo.getInstance(contentInfo.contentType),
                        ImageDataObjIdInfo.getInstance(contentSequence.first() as DLSequence),
                        AlgorithmInfo(
                            (AlgorithmIdentifier.getInstance(
                                algorithmSequence.first()
                            ))
                        ),
                        TextualInfo.getInstance(algorithmSequence.getObjectAt(1))
                    )
                }
            }
    }

    override fun getContentPrimitive() =
        listOf(
            imageDataObjIdInfo.toPrimitive(),
            listOf(
                hashAlgorithmInfo.toPrimitive(),
                contentHash.toPrimitive()
            ).toDLSequence()
        ).toDLSequence()
}