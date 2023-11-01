package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.crypt.Utils.ConvertToDate
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.pkcs.RSAPublicKey
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.jetbrains.annotations.NotNull
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.time.Clock
import java.time.LocalDateTime
import java.util.*

open class FakePki {
  companion object {
    private val RSA_ENCRYPTION = ASN1ObjectIdentifier("1.2.840.113549.1.1.1")
    private val SHA1_WITH_RSA_SIGNATURE = ASN1ObjectIdentifier("1.2.840.113549.1.1.5")
    private const val publicKeyLength = 1024

    fun CreateRoot(@NotNull name: String, utcValidFrom: Date, utcValidTo: Date): FakePki {
      if (utcValidFrom >= utcValidTo)
        throw IllegalArgumentException("utcValidTo must be greater then utcValidFrom")

      return FakePki(name, utcValidFrom, utcValidTo)
    }

    private fun getNewPair(): KeyPair {
      val keyGen = KeyPairGenerator.getInstance("RSA")
      keyGen.initialize(publicKeyLength, SecureRandom.getInstance("SHA1PRNG"))
      return keyGen.generateKeyPair()
    }
  }

  private val _keyPair: KeyPair = getNewPair()
  private val _signatureAlg = AlgorithmIdentifier(SHA1_WITH_RSA_SIGNATURE)
  private var _certificate: X509CertificateHolder

  val Certificate: X509CertificateHolder
    get() = _certificate

  var _crl: X509CRLHolder? = null

  var Crl: X509CRLHolder?
    get() = _crl
    set(value) {
      _crl = value
    }

  private val _certificates = mutableListOf<X509CertificateHolder>()

  val IssuedCertificates: Collection<X509CertificateHolder>
    get() = _certificates

  private val RevokedCertificates = mutableMapOf<BigInteger, Date>()

  constructor(name: String, validFrom: Date, validTo: Date) {
    val subject = X500Name("CN=${name}")
    val res = enroll(subject, _keyPair, name, validFrom, validTo, 0, false, false)
    _certificate = res
    Crl = createCrl()
  }

  fun Enroll(name: String, validFrom: Date, validTo: Date, codeSign: Boolean): Pair<KeyPair, X509CertificateHolder> {
    val keyPair = getNewPair()
    val certificate = enroll(Certificate.subject, keyPair, name, validFrom, validTo, (_certificates.count() + 1).toLong(), true, codeSign)
    _certificates.add(certificate)
    return Pair(keyPair, certificate)
  }

  fun Revoke(@NotNull certificate: X509CertificateHolder, renewCrl: Boolean) {
    if (isIssued(certificate)) {
      RevokedCertificates.put(certificate.serialNumber, LocalDateTime.now().ConvertToDate())
      if (renewCrl) {
        Crl = createCrl()
      }
    }
  }

  fun UpdateCrl() {
    Crl = createCrl()
  }

  private fun isIssued(certificate: X509CertificateHolder): Boolean {
    return certificate.issuer.equals(Certificate.subject)
  }

  private fun enroll(issuerDN: X500Name, keyPair: KeyPair, subjectName: String, validFrom: Date, validTo: Date, sn: Long, addCrlDp: Boolean, codeSign: Boolean): X509CertificateHolder {
    val version = DERTaggedObject(0, ASN1Integer(2))
    val serialNumber = ASN1Integer(sn)
    val startDate = Time(validFrom)
    val endDate = Time(validTo)
    val dates = DERSequence(arrayOf(startDate, endDate))
    val subject = X500Name("CN=${subjectName}")
    val alg = AlgorithmIdentifier(RSA_ENCRYPTION)
    val rsaKeyParameters = keyPair.public as java.security.interfaces.RSAPublicKey
    val keyData = RSAPublicKey(rsaKeyParameters.modulus, rsaKeyParameters.publicExponent).encoded
    val subjectPublicKeyInfo = SubjectPublicKeyInfo(alg, keyData)
    val vec = ASN1EncodableVector().also { it.addAll(arrayOf(version, serialNumber, _signatureAlg, issuerDN, dates, subject, subjectPublicKeyInfo)) }
    val extValues = mutableListOf<Extension>()

    if (addCrlDp) {
      val names = GeneralNames(GeneralName(GeneralName.uniformResourceIdentifier, DERIA5String("http://fakepki/crl")))
      val crlDistPoint = CRLDistPoint(arrayOf(DistributionPoint(DistributionPointName(DistributionPointName.FULL_NAME, names), null, null)))
      extValues.add(Extension.create(Extension.cRLDistributionPoints, false, crlDistPoint))
    }

    if (codeSign) {
      extValues.add(Extension.create(Extension.extendedKeyUsage, false, DERSequence(KeyPurposeId.id_kp_codeSigning)))
    }

    if (extValues.any()) {
      val ext = Extensions(extValues.toTypedArray())
      vec.addOptionalTagged(true, 3, ext)
    }

    val seq = DERSequence(vec)
    val tbs = TBSCertificate.getInstance(seq)
    val tbsData = tbs.encoded
    val sig = sign(tbsData, _keyPair)
    val cs =
      org.bouncycastle.asn1.x509.Certificate.getInstance(getDerSequenceInstance(tbs, _signatureAlg, DERBitString(sig)))
    return X509CertificateHolder(cs)
  }

  private fun createCrl(): X509CRLHolder {
    val version = ASN1Integer(1)
    val issuer = Certificate.subject
    val now = LocalDateTime.now(Clock.systemUTC()).plusMinutes(1)
    val thisUpdate = Time(now.ConvertToDate())
    val nextUpdate = Time(now.plusDays(5).ConvertToDate())
    val revokedCertificates = getRevokedCertificates()
    val seq = getDerSequenceInstance(version, _signatureAlg, issuer, thisUpdate, nextUpdate, revokedCertificates)
    val tbs = TBSCertList.getInstance(seq)
    val tbsData = tbs.encoded
    val sig = sign(tbsData, _keyPair)
    val certList = CertificateList.getInstance(getDerSequenceInstance(tbs, _signatureAlg, DERBitString(sig)))
    return X509CRLHolder(certList)
  }

  private fun getRevokedCertificates(): DERSequence {
    val vec = RevokedCertificates.map { s -> getRevokedCertificate(s.key, s.value) }.toAsn1EncodableVector()
    return DERSequence(vec)
  }

  private fun getRevokedCertificate(serialNumber: BigInteger, revocationTime: Date): DERSequence {
    return DERSequence(arrayOf(ASN1Integer(serialNumber), Time(revocationTime)))
  }

  private fun sign(data: ByteArray, key: KeyPair): ByteArray {
    val signature = Signature.getInstance(_signatureAlg.algorithm.id).also { it.initSign(key.private) }
    signature.update(data)
    return signature.sign()
  }

  private fun ASN1EncodableVector.addOptionalTagged(isExplicit: Boolean, tagNo: Int, obj: ASN1Encodable?) {
    if (null != obj) {
      this.add(DERTaggedObject(isExplicit, tagNo, obj))
    }
  }

  private fun Collection<ASN1Encodable>.toAsn1EncodableVector(): ASN1EncodableVector {
    val v = ASN1EncodableVector()
    forEach { v.add(it) }
    return v
  }

  private fun getDerSequenceInstance(vararg asn1Encodable: ASN1Encodable): DERSequence {
    return DERSequence(ASN1EncodableVector().also { it.addAll(asn1Encodable) })
  }
}
