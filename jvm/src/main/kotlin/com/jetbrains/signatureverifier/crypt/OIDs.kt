package com.jetbrains.signatureverifier.crypt

import org.bouncycastle.asn1.ASN1ObjectIdentifier

object OIDs {
  val SPC_INDIRECT_DATA: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.1.4")
  val SPC_NESTED_SIGNATURE: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.4.1")
  val SIGNING_TIME: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.2.840.113549.1.9.5")
  val MS_COUNTER_SIGN: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.3.6.1.4.1.311.3.3.1")
  val TIMESTAMP_TOKEN: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14")
  val EXTENDED_KEY_USAGE: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.29.37")
  val APPLE_CERTIFICATE_EXTENSION_CODE_SIGNING: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.2.840.113635.100.6.1.13")
  val APPLE_CERTIFICATE_EXTENSION_KEXT_SIGNING: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.2.840.113635.100.6.1.18")
  val OCSP: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1")
}

