package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.Resources
import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.math.BigInteger

class CertFromResources {

  private val expectations = mapOf(

    Pair(
      BigInteger("0444c0", 16),
      "C=PL,O=Unizeto Technologies S.A.,OU=Certum Certification Authority,CN=Certum Trusted Network CA"
    ),
    Pair(
      BigInteger("02", 16),
      "C=US,O=Apple Inc.,OU=Apple Certification Authority,CN=Apple Root CA"
    ),
    Pair(
      BigInteger("4a538c28", 16),
      "CN=Entrust Root Certification Authority - G2, OU=\"(c) 2009 Entrust, Inc. - for authorized use only\", OU=See www.entrust.net/legal-terms, O=\"Entrust, Inc.\", C=US"
    ),
    Pair(
      BigInteger("00", 16),
      "C=US,ST=Arizona,L=Scottsdale,O=\"GoDaddy.com, Inc.\",CN=Go Daddy Root Certificate Authority - G2"
    ),
    Pair(
      BigInteger("01fd6d30fca3ca51a81bbc640e35032d", 16),
      "C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority"
    ),
    Pair(
      BigInteger("56b629cd34bc78f6", 16),
      "C=US,ST=Texas,L=Houston,O=SSL Corporation,CN=SSL.com EV Root Certification Authority RSA R2"
    ),
    Pair(
      BigInteger("28cc3a25bfba44ac449a9b586b4339aa", 16),
      "C=US,ST=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Root Certificate Authority 2010"
    ),
    Pair(
      BigInteger("3f8bc8b5fc9fb29643b569d66c42e144", 16),
      "C=US,ST=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Root Certificate Authority 2011"
    ),
    Pair(
      BigInteger("79ad16a14aa0a5ad4c7358f407132e65", 16),
      "DC=com,DC=microsoft,CN=Microsoft Root Certificate Authority"
    )
  )

  //Performs cert matching. Splits by comma and verifies that N=V pairs are the same.
  //It's needed because on JVM the order of pairs in string representation of certificate is different.

  private fun certContentMatches(left: String, right: String): Boolean {
    return right.split(",").map { it.trim() }.containsAll(left.split(",").map { it.trim() })
  }

  @Test
  fun verifyCertsInResources() {

    SignatureVerificationParams(
      Resources.GetDefaultRoots(),
      withRevocationCheck = false
    ).RootCertificates?.map {
      it.trustedCert
    }?.forEach {
      Assertions.assertTrue(
        expectations.containsKey(it.serialNumber),
        "Certificate serial number ${it.serialNumber.toString(16)} is on the known serial numbers list"
      )
      Assertions.assertTrue(
        certContentMatches(expectations[it.serialNumber].toString(), it.issuerDN.toString()),
        "Certificate with serial number ${it.serialNumber.toString(16)} contents matches what we expect"
      )
    }
  }
}