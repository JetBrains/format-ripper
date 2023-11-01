package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.Resources
import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.math.BigInteger

class DefaultRootsTest {
  @Test
  fun test() {
    val expectedCertificates = arrayOf(
      // @formatter:off
      Pair("Apple Root CA"                            , BigInteger("02"                              , 16)),
      Pair("Certum Trusted Network CA"                , BigInteger("0444c0"                          , 16)),
      Pair("Entrust Root Certification Authority - G2", BigInteger("4a538c28"                        , 16)),
      Pair("Go Daddy Root Certificate Authority - G2" , BigInteger("00"                              , 16)),
      Pair("Microsoft Root Certificate Authority"     , BigInteger("79ad16a14aa0a5ad4c7358f407132e65", 16)),
      Pair("Microsoft Root Certificate Authority 2010", BigInteger("28cc3a25bfba44ac449a9b586b4339aa", 16)),
      Pair("Microsoft Root Certificate Authority 2011", BigInteger("3f8bc8b5fc9fb29643b569d66c42e144", 16)),
      Pair("USERTrust RSA Certification Authority"    , BigInteger("01fd6d30fca3ca51a81bbc640e35032d", 16))
      // @formatter:on
    )

    val cnRegex = Regex("CN=(?<CN>[^,]*)")
    val certificates = SignatureVerificationParams(
      Resources.GetDefaultRoots(),
      withRevocationCheck = false
    ).RootCertificates!!.map {
      it.trustedCert
    }.map {
      val name = cnRegex.find(it.issuerDN.name)!!.groups["CN"]!!.value
      Pair(name, it.serialNumber)
    }.sortedBy { it.first }.toList()

    Assertions.assertEquals(expectedCertificates.size, certificates.size)
    for (n in certificates.indices) {
      Assertions.assertEquals(expectedCertificates[n].first, certificates[n].first)
      Assertions.assertEquals(expectedCertificates[n].second, certificates[n].second)
    }
  }
}