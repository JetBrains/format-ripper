package com.jetbrains.signatureverifier.crypt

import com.jetbrains.signatureverifier.ILogger
import com.jetbrains.signatureverifier.NullLogger
import org.bouncycastle.cms.SignerInformationStore
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.util.Store
import org.jetbrains.annotations.NotNull
import org.jetbrains.annotations.Nullable

open class SignedMessageVerifier {
  private val _crlProvider: CrlProvider
  private val _logger: ILogger

  constructor(@Nullable logger: ILogger) : this(CrlProvider(logger), logger)

  constructor(@NotNull crlProvider: CrlProvider, @Nullable logger: ILogger?) {
    _crlProvider = crlProvider
    _logger = logger ?: NullLogger.Instance
  }

  suspend fun VerifySignatureAsync(
    @NotNull signedMessage: SignedMessage,
    @NotNull signatureVerificationParams: SignatureVerificationParams
  ): VerifySignatureResult {
    _logger.Trace("Verify with params: $signatureVerificationParams")
    val certs = signedMessage.SignedData.certificates
    val signersStore = signedMessage.SignedData.signerInfos
    return verifySignatureAsync(signersStore, certs, signatureVerificationParams)
  }

  private suspend fun verifySignatureAsync(
    signersStore: SignerInformationStore,
    certs: Store<X509CertificateHolder>,
    signatureVerificationParams: SignatureVerificationParams
  ): VerifySignatureResult {
    for (signer in signersStore.signers) {
      val siv = SignerInfoVerifier(signer, certs, _crlProvider, _logger)
      val result = siv.VerifyAsync(signatureVerificationParams)
      if (result != VerifySignatureResult.Valid)
        return result
    }
    return VerifySignatureResult.Valid
  }
}

