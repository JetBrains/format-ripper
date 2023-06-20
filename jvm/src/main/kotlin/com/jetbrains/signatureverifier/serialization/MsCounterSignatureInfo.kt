package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.AttributeCertificate
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.cert.X509CertificateHolder

@Serializable
data class MsCounterSignatureInfo(
  val version: Int,
  val algorithms: List<AlgorithmInfo>,
  val tstInfo: TSTInfo,
  val taggedCertificateInfo: TaggedObjectInfo,
  val counterSignatures: List<CounterSignatureInfo>

) : EncodableInfo {
  companion object {
    fun getInstance(sequence: DLSequence): MsCounterSignatureInfo {
      val iterator = sequence.iterator()

      val version = (iterator.next() as ASN1Integer).intValueExact()

      val algorithms = (iterator.next() as DLSet).map {
        AlgorithmInfo(
          AlgorithmIdentifier.getInstance(it)
        )
      }

      val tstInfo = TSTInfo(iterator.next() as DLSequence)

      val wtf = iterator.next()
      val taggedCertificateInfo = wtf.let {
        TaggedObjectInfo(
          TaggedObjectMetaInfo(it as DLTaggedObject),
          SequenceInfo(
            (it.baseObject as DLSequence).map { certificateSequence ->
              when (certificateSequence) {
                is DLSequence -> {
                  CertificateInfo.getInstance(
                    X509CertificateHolder(
                      Certificate.getInstance(
                        certificateSequence
                      )
                    )
                  )
                }

                is DLTaggedObject -> {
                  TaggedObjectInfo(
                    TaggedObjectMetaInfo(certificateSequence),
                    CertificateInfo.getInstance(
                      X509AttributeCertificateHolder(
                        AttributeCertificate.getInstance(
                          certificateSequence.baseObject
                        )
                      )
                    )
                  )
                }

                else -> throw Exception("Unexpected certificate primitive")
              }

            }
          )
        )

      }

      val counterSignatures = (iterator.next() as DLSet).map {
        CounterSignatureInfo.getInstance(it as DLSequence)
      }

      println()
      return MsCounterSignatureInfo(
        version,
        algorithms,
        tstInfo,
        taggedCertificateInfo,
        counterSignatures
      )
    }

  }

  override fun toPrimitive(): ASN1Primitive = listOf(
    ASN1Integer(version.toLong()),
    algorithms.map { it.toPrimitive() }.toDLSet(),
    tstInfo.toPrimitive(),
    taggedCertificateInfo.toPrimitive(),
    counterSignatures.map { it.toPrimitive() }.toDLSet()
  ).toDLSequence()
}