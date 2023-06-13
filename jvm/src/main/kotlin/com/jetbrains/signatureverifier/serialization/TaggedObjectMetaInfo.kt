import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DLTaggedObject

/**
 * This whole class exists, because org.bouncycastle.asn1.ASN1TaggedObject
 * has different explicitness types for different modes,
 * yet you can not access neither the explicitness field itself, nor isParsed() method
 * needed to reproduce the same value.
 * We, of course, need this value to recreate byte-identical instance of DLTaggedObject
 * from serialized data.
 */
data class TaggedObjectMetaInfo(
  val tagNo: Int,
  val explicitness: Int
) {
  companion object {
    fun getExplicitness(obj: ASN1TaggedObject): Int {
      val explicitnessField = ASN1TaggedObject::class.java.getDeclaredField("explicitness")
      explicitnessField.isAccessible = true
      return explicitnessField.get(obj) as Int
    }
  }

  constructor(obj: DLTaggedObject) : this(obj.tagNo, getExplicitness(obj))
}