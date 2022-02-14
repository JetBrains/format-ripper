package com.jetbrains.signatureverifier.crypt

import java.security.cert.Certificate
import java.security.cert.PKIXCertPathChecker

class CustomPkixCertPathChecker : PKIXCertPathChecker() {
  override fun init(forward: Boolean) {
  }

  override fun isForwardCheckingSupported(): Boolean {
    return false
  }

  override fun getSupportedExtensions(): MutableSet<String> {
    return mutableSetOf()
  }

  override fun check(cert: Certificate?, unresolvedCritExts: MutableCollection<String>) {
    unresolvedCritExts.remove(OIDs.EXTENDED_KEY_USAGE.id)
    unresolvedCritExts.remove(OIDs.APPLE_CERTIFICATE_EXTENSION_CODE_SIGNING.id)
    unresolvedCritExts.remove(OIDs.APPLE_CERTIFICATE_EXTENSION_KEXT_SIGNING.id)
  }
}
