import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DLTaggedObject

data class TaggedObjectMetaInfo(
  val tagNo: Int,
  val explicitness: Int
) {
  companion object {
    private const val DECLARED_EXPLICIT = 1
    private const val DECLARED_IMPLICIT = 2
    private const val PARSED_EXPLICIT = 3
    private const val PARSED_IMPLICIT = 4

    fun getExplicitness(obj: ASN1TaggedObject): Int {
      val explicitnessField = ASN1TaggedObject::class.java.getDeclaredField("explicitness")
      explicitnessField.isAccessible = true

      return explicitnessField.get(obj) as Int
    }

    /**
     * Hack to get same explicitness as in original
     */
    fun getTaggedObjectWithMetaInfo(
      metaInfo: TaggedObjectMetaInfo,
      content: ASN1Encodable
    ): DLTaggedObject = when (metaInfo.explicitness) {
      DECLARED_EXPLICIT -> DLTaggedObject(true, metaInfo.tagNo, content)
      DECLARED_IMPLICIT -> DLTaggedObject(false, metaInfo.tagNo, content)

      PARSED_EXPLICIT -> DLTaggedObject.getInstance(
        DLTaggedObject(true, metaInfo.tagNo, content).encoded
      ) as DLTaggedObject

      PARSED_IMPLICIT -> DLTaggedObject.getInstance(
        DLTaggedObject(false, metaInfo.tagNo, content).encoded
      ) as DLTaggedObject

      else -> throw Exception("Tagged object explicitness can only be 1, 2, 3 or 4")
    }
  }

  constructor(obj: DLTaggedObject) : this(obj.tagNo, getExplicitness(obj))
}