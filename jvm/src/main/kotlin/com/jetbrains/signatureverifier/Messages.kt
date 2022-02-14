package com.jetbrains.signatureverifier

internal object Messages {
  val unknown_certificate_revocation_status = "Unknown certificate revocation status"
  val invalid_ocsp_response = "Invalid OCSP response"
  val unable_determin_certificate_revocation_status = "Unable to determine certificate revocation status"
  val certificate_revoked = "Certificate has been revoked at {0}. {1}"
  val signer_cert_not_found = "Signer's certificate not found"
}