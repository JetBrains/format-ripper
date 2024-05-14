package com.jetbrains.signatureverifier.bouncycastle.cms

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers
import org.bouncycastle.asn1.eac.EACObjectIdentifiers
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.AttributeCertificate
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.asn1.x509.CertificateList
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder
import org.bouncycastle.util.CollectionStore
import org.bouncycastle.util.Store

internal class CMSSignedHelper {
  /**
   * Return the digest encryption algorithm using one of the standard
   * JCA string representations rather the the algorithm identifier (if
   * possible).
   */
  fun getEncryptionAlgName(
    encryptionAlgOID: String
  ): String {
    val algName = encryptionAlgs[encryptionAlgOID] as String?
    return algName ?: encryptionAlgOID
  }

  fun fixDigestAlgID(algId: AlgorithmIdentifier, dgstAlgFinder: DigestAlgorithmIdentifierFinder): AlgorithmIdentifier {
    val params = algId.parameters
    return if (params == null || DERNull.INSTANCE.equals(params)) {
      dgstAlgFinder.find(algId.algorithm)
    } else {
      algId
    }
  }

  fun setSigningEncryptionAlgorithmMapping(oid: ASN1ObjectIdentifier, algorithmName: String) {
    addEntries(oid, algorithmName)
  }

  fun getCertificates(certSet: ASN1Set?): Store<X509CertificateHolder> {
    if (certSet != null) {
      val certList = mutableListOf<X509CertificateHolder>()
      val en = certSet.objects
      while (en.hasMoreElements()) {
        val obj = (en.nextElement() as ASN1Encodable).toASN1Primitive()
        if (obj is ASN1Sequence) {
          certList.add(X509CertificateHolder(Certificate.getInstance(obj)))
        }
      }
      return CollectionStore(certList)
    }
    return CollectionStore(arrayListOf())
  }

  fun getAttributeCertificates(certSet: ASN1Set?): Store<X509AttributeCertificateHolder> {
    if (certSet != null) {
      val certList = mutableListOf<X509AttributeCertificateHolder>()
      val en = certSet.objects
      while (en.hasMoreElements()) {
        val obj = (en.nextElement() as ASN1Encodable).toASN1Primitive()
        if (obj is ASN1TaggedObject) {
          certList.add(X509AttributeCertificateHolder(AttributeCertificate.getInstance(obj.baseObject)))
        }
      }
      return CollectionStore(certList)
    }
    return CollectionStore(arrayListOf())
  }

  fun getCRLs(crlSet: ASN1Set?): Store<X509CRLHolder> {
    if (crlSet != null) {
      val crlList = mutableListOf<X509CRLHolder>()
      val en = crlSet.objects
      while (en.hasMoreElements()) {
        val obj = (en.nextElement() as ASN1Encodable).toASN1Primitive()
        if (obj is ASN1Sequence) {
          crlList.add(X509CRLHolder(CertificateList.getInstance(obj)))
        }
      }
      return CollectionStore(crlList)
    }
    return CollectionStore(arrayListOf())
  }

  fun getOtherRevocationInfo(otherRevocationInfoFormat: ASN1ObjectIdentifier, crlSet: ASN1Set?): Store<*> {
    if (crlSet != null) {
      val crlList = mutableListOf<ASN1Encodable>()
      val en = crlSet.objects
      while (en.hasMoreElements()) {
        val obj = (en.nextElement() as ASN1Encodable).toASN1Primitive()
        if (obj is ASN1TaggedObject) {
          val tObj = ASN1TaggedObject.getInstance(obj)
          if (tObj.tagNo == 1) {
            val other = OtherRevocationInfoFormat.getInstance(tObj, false)
            if (otherRevocationInfoFormat.equals(other.infoFormat)) {
              crlList.add(other.info)
            }
          }
        }
      }
      return CollectionStore(crlList)
    }
    return CollectionStore(ArrayList<Any?>())
  }

  companion object {
    @JvmField
    val INSTANCE = CMSSignedHelper()
    private val encryptionAlgs = HashMap<String, String>()
    private fun addEntries(alias: ASN1ObjectIdentifier, encryption: String) {
      encryptionAlgs[alias.id] = encryption
    }

    init {
      addEntries(NISTObjectIdentifiers.dsa_with_sha224, "DSA")
      addEntries(NISTObjectIdentifiers.dsa_with_sha256, "DSA")
      addEntries(NISTObjectIdentifiers.dsa_with_sha384, "DSA")
      addEntries(NISTObjectIdentifiers.dsa_with_sha512, "DSA")
      addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_224, "DSA")
      addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_256, "DSA")
      addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_384, "DSA")
      addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_512, "DSA")
      addEntries(OIWObjectIdentifiers.dsaWithSHA1, "DSA")
      addEntries(OIWObjectIdentifiers.md4WithRSA, "RSA")
      addEntries(OIWObjectIdentifiers.md4WithRSAEncryption, "RSA")
      addEntries(OIWObjectIdentifiers.md5WithRSA, "RSA")
      addEntries(OIWObjectIdentifiers.sha1WithRSA, "RSA")
      addEntries(PKCSObjectIdentifiers.md2WithRSAEncryption, "RSA")
      addEntries(PKCSObjectIdentifiers.md4WithRSAEncryption, "RSA")
      addEntries(PKCSObjectIdentifiers.md5WithRSAEncryption, "RSA")
      addEntries(PKCSObjectIdentifiers.sha1WithRSAEncryption, "RSA")
      addEntries(PKCSObjectIdentifiers.sha224WithRSAEncryption, "RSA")
      addEntries(PKCSObjectIdentifiers.sha256WithRSAEncryption, "RSA")
      addEntries(PKCSObjectIdentifiers.sha384WithRSAEncryption, "RSA")
      addEntries(PKCSObjectIdentifiers.sha512WithRSAEncryption, "RSA")
      addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, "RSA")
      addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, "RSA")
      addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, "RSA")
      addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, "RSA")
      addEntries(X9ObjectIdentifiers.ecdsa_with_SHA1, "ECDSA")
      addEntries(X9ObjectIdentifiers.ecdsa_with_SHA224, "ECDSA")
      addEntries(X9ObjectIdentifiers.ecdsa_with_SHA256, "ECDSA")
      addEntries(X9ObjectIdentifiers.ecdsa_with_SHA384, "ECDSA")
      addEntries(X9ObjectIdentifiers.ecdsa_with_SHA512, "ECDSA")
      addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, "ECDSA")
      addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, "ECDSA")
      addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, "ECDSA")
      addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, "ECDSA")
      addEntries(X9ObjectIdentifiers.id_dsa_with_sha1, "DSA")
      addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "ECDSA")
      addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "ECDSA")
      addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "ECDSA")
      addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "ECDSA")
      addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "ECDSA")
      addEntries(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, "RSA")
      addEntries(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, "RSA")
      addEntries(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_1, "RSAandMGF1")
      addEntries(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256, "RSAandMGF1")
      addEntries(X9ObjectIdentifiers.id_dsa, "DSA")
      addEntries(PKCSObjectIdentifiers.rsaEncryption, "RSA")
      addEntries(TeleTrusTObjectIdentifiers.teleTrusTRSAsignatureAlgorithm, "RSA")
      addEntries(X509ObjectIdentifiers.id_ea_rsa, "RSA")
      addEntries(PKCSObjectIdentifiers.id_RSASSA_PSS, "RSAandMGF1")
      addEntries(CryptoProObjectIdentifiers.gostR3410_94, "GOST3410")
      addEntries(CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410")
      addEntries(ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.6.2"), "ECGOST3410")
      addEntries(ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.1.5"), "GOST3410")
      addEntries(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, "ECGOST3410-2012-256")
      addEntries(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, "ECGOST3410-2012-512")
      addEntries(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "ECGOST3410")
      addEntries(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3410")
      addEntries(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "ECGOST3410-2012-256")
      addEntries(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "ECGOST3410-2012-512")
    }
  }
}