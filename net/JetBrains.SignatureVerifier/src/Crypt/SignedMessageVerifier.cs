using System;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using JetBrains.SignatureVerifier.Crypt.BC;
using Org.BouncyCastle.X509.Store;

namespace JetBrains.SignatureVerifier.Crypt
{
  public static class Extension
  {
    public static string ToHexString(this byte[] bytes)
    {
      var hexChars = "0123456789ABCDEF";
      var result = new StringBuilder(bytes.Length * 2);

      foreach (var b in bytes)
      {
        var value = b & 0xFF;
        result.Append(hexChars[value >> 4]);
        result.Append(hexChars[value & 0x0F]);
      }

      return result.ToString();
    }
  }
  public class SignedMessageVerifier
  {
    private readonly CrlProvider _crlProvider;
    private readonly ILogger _logger;

    public SignedMessageVerifier([CanBeNull] ILogger logger)
      : this(new CrlProvider(logger), logger)
    {
    }

    public SignedMessageVerifier([NotNull] CrlProvider crlProvider, [CanBeNull] ILogger logger)
    {
      _crlProvider = crlProvider ?? throw new ArgumentNullException(nameof(crlProvider));
      _logger = logger ?? NullLogger.Instance;
    }

    public Task<VerifySignatureResult> VerifySignatureAsync(
      [NotNull] SignedMessage signedMessage,
      [NotNull] SignatureVerificationParams signatureVerificationParams)
    {
      if (signedMessage == null)
        throw new ArgumentNullException(nameof(signedMessage));

      if (signatureVerificationParams == null)
        throw new ArgumentNullException(nameof(signatureVerificationParams));

      _logger?.Trace($"Verify with params: {signatureVerificationParams}");

      var certs = signedMessage.SignedData.GetCertificates("Collection");
      var signersStore = signedMessage.SignedData.GetSignerInfos();
      return verifySignatureAsync(signersStore, certs, signatureVerificationParams);
    }

    private async Task<VerifySignatureResult> verifySignatureAsync(
      SignerInformationStore signersStore,
      IX509Store certs,
      SignatureVerificationParams signatureVerificationParams)
    {
      foreach (SignerInformation signer in signersStore.GetSigners())
      {
        var siv = new SignerInfoVerifier(signer, certs, _crlProvider, _logger);
        var result = await siv.VerifyAsync(signatureVerificationParams);

        if (result != VerifySignatureResult.Valid)
          return result;
      }

      return VerifySignatureResult.Valid;
    }
  }
}