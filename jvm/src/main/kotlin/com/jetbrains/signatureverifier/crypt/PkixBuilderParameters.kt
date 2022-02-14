package com.jetbrains.signatureverifier.crypt

import com.jetbrains.signatureverifier.crypt.BcExt.IsSelfSigned
import com.jetbrains.signatureverifier.crypt.BcExt.ToJavaCertStore
import com.jetbrains.signatureverifier.crypt.BcExt.ToJavaCrlStore
import com.jetbrains.signatureverifier.crypt.BcExt.ToX509CertificateHolder
import com.jetbrains.signatureverifier.crypt.Utils.ConvertToDate
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.util.CollectionStore
import org.bouncycastle.util.Store
import org.jetbrains.annotations.NotNull
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXCertPathChecker
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.time.LocalDateTime

class CustomPkixBuilderParameters : PKIXBuilderParameters {
  private val _intermediateCertsStore: Store<X509CertificateHolder>
  private val _primaryCert: X509CertSelector

  constructor(
    @NotNull rootCertificates: HashSet<TrustAnchor>,
    @NotNull intermediateCertsStore: Store<X509CertificateHolder>,
    @NotNull primaryCert: X509CertSelector,
    signValidationTime: LocalDateTime?
  ) : super(rootCertificates, primaryCert) {
    _intermediateCertsStore = intermediateCertsStore
    _primaryCert = primaryCert

    if (signValidationTime != null)
      date = signValidationTime.ConvertToDate()

    isRevocationEnabled = false
    addCertStore(intermediateCertsStore.ToJavaCertStore())
    addCertPathChecker(CustomPkixCertPathChecker())
    policyQualifiersRejected = false
  }

  /**
   * Prepare CRLs for all certificates
   *
   * @param crlProvider  CrlProvider for CRLs consume
   * @return
   *     True if CRLs successfully added to the params, False if CRLs can not be used (and OCSP is considered)
   */
  suspend fun PrepareCrls(@NotNull crlProvider: CrlProvider): Boolean {
    val certs = _intermediateCertsStore.getMatches(null).toMutableList()
    certs.add(_primaryCert.certificate.ToX509CertificateHolder())
    certs.removeAll { cert -> cert.IsSelfSigned() }
    val allCerts = certs.distinctBy { cert -> cert.issuer.toString() to cert.serialNumber }
    val allCrls = getCrlsForCertsAsync(crlProvider, allCerts) ?: return true
    val crlStore = CollectionStore(allCrls)
    addCertStore(crlStore.ToJavaCrlStore())
    isRevocationEnabled = true
    return false
  }

  override fun getCertPathCheckers(): MutableList<PKIXCertPathChecker> {
    val cpc = CustomPkixCertPathChecker()
    return mutableListOf(cpc)
  }

  private suspend fun getCrlsForCertsAsync(
    crlProvider: CrlProvider,
    allCerts: Collection<X509CertificateHolder>
  ): Collection<X509CRLHolder>? {
    val allCrls = mutableListOf<X509CRLHolder>()
    for (cert in allCerts) {
      val crls = crlProvider.GetCrlsAsync(cert).filter { crl -> crl.thisUpdate.before(cert.notAfter) }.toList()
      //if any certificate won't check with CRL - reject others
      if (crls.count() == 0)
        return null

      allCrls.addAll(crls)
    }
    return allCrls.distinctBy { crl -> crl.issuer.toString() }
  }
}

