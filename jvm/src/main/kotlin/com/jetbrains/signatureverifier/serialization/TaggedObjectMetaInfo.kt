
import com.jetbrains.signatureverifier.serialization.getExplicitness
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1TaggedObject

/**
 * This whole class exists, because org.bouncycastle.asn1.ASN1TaggedObject
 * has different explicitness types for different modes,
 * yet you can not access neither the explicitness field itself, nor isParsed() method
 * needed to reproduce the same value.
 * We, of course, need this value to recreate byte-identical instance of DLTaggedObject
 * from serialized data.
 */
@Serializable
data class TaggedObjectMetaInfo(
  val tagNo: Int,
  val explicitness: Int
) {

  constructor(obj: ASN1TaggedObject) : this(obj.tagNo, obj.getExplicitness())
}