using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace JetBrains.SignatureVerifier.Crypt
{
  public class OcspVerifier
  {
    private static readonly string OCSP_REQUEST_TYPE = "application/ocsp-request";
    private static readonly string OCSP_RESPONSE_TYPE = "application/ocsp-response";
    private TimeSpan _ocspResponseTimeout;
    private readonly ILogger _logger;
    private TimeSpan ocspResponseCorrectSpan = TimeSpan.FromMinutes(1);

    public OcspVerifier(TimeSpan ocspResponseTimeout, ILogger logger)
    {
      _ocspResponseTimeout = ocspResponseTimeout;
      _logger = logger ?? NullLogger.Instance;
    }

    public async Task<VerifySignatureResult> CheckCertificateRevocationStatusAsync([NotNull] X509Certificate targetCert,
      [NotNull] X509Certificate issuerCert)
    {
      if (targetCert == null) throw new ArgumentNullException(nameof(targetCert));
      if (issuerCert == null) throw new ArgumentNullException(nameof(issuerCert));

      var ocspUrl = targetCert.GetOcspUrl();

      if (ocspUrl is null)
      {
        _logger.Warning($"The OCSP access data is empty in certificate {targetCert.FormatId()}");
        _logger.Error(Messages.unable_determin_certificate_revocation_status);
        return VerifySignatureResult.InvalidChain(Messages.unable_determin_certificate_revocation_status);
      }

      var ocspReqGenerator = new Org.BouncyCastle.Ocsp.OcspReqGenerator();
      var certificateIdReq =
        new CertificateID(OiwObjectIdentifiers.IdSha1.Id, issuerCert, targetCert.SerialNumber);
      ocspReqGenerator.AddRequest(certificateIdReq);
      var ocspReq = ocspReqGenerator.Generate();

      var ocspRes = await getOcspResponceAsync(ocspUrl, ocspReq, _ocspResponseTimeout);

      if (ocspRes.Status != OcspRespStatus.Successful)
      {
        _logger.Error($"OCSP response status: {ocspRes.Status}");
        return VerifySignatureResult.InvalidChain(Messages.unable_determin_certificate_revocation_status);
      }

      var basicOcspResp = ocspRes.GetResponseObject() as BasicOcspResp;

      if (basicOcspResp is null)
      {
        _logger.Error($"Unknown OCSP response type");
        return VerifySignatureResult.InvalidChain(Messages.unable_determin_certificate_revocation_status);
      }

      if (!validateOcspResponse(basicOcspResp))
        return VerifySignatureResult.InvalidChain(Messages.invalid_ocsp_response);

      var singleResponses = basicOcspResp.Responses.Where(w => w.GetCertID().Equals(certificateIdReq)).ToList();

      if (singleResponses.Count < 1)
      {
        _logger.Error("OCSP response not correspond to request");
        return VerifySignatureResult.InvalidChain(Messages.invalid_ocsp_response);
      }

      foreach (var singleResp in singleResponses)
      {
        if (!validateSingleOcspResponse(singleResp))
          return VerifySignatureResult.InvalidChain(Messages.invalid_ocsp_response);

        var certStatus = singleResp.GetCertStatus();

        //null is good
        if (certStatus is null)
        {
          continue;
        }
        else if (certStatus is UnknownStatus)
        {
          _logger.Warning(Messages.unknown_certificate_revocation_status);
          return VerifySignatureResult.InvalidChain(Messages.unknown_certificate_revocation_status);
        }
        else if (certStatus is RevokedStatus)
        {
          var certRevStatus = certStatus as RevokedStatus;
          var msg = formatRevokedStatus(certRevStatus);
          _logger.Warning(msg);
          return VerifySignatureResult.InvalidChain(msg);
        }
      }

      return VerifySignatureResult.Valid;
    }

    private async Task<OcspResp> getOcspResponceAsync(string ocspResponderUrl, OcspReq request, TimeSpan timeout)
    {
      if (!ocspResponderUrl.StartsWith("http"))
      {
        _logger.Error("Only http(s) is supported for OCSP calls");
        return null;
      }

      _logger.Trace($"OCSP request: {ocspResponderUrl}");

      try
      {
        byte[] array = request.GetEncoded();
        using var httpClient = new HttpClient();
        httpClient.Timeout = timeout;
        httpClient.DefaultRequestHeaders.Accept.Add(
          new MediaTypeWithQualityHeaderValue(OCSP_RESPONSE_TYPE));
        var content = new ByteArrayContent(array);
        content.Headers.ContentType = new MediaTypeHeaderValue(OCSP_REQUEST_TYPE);
        var response = await httpClient.PostAsync(ocspResponderUrl, content);
        var responseStream = await response.Content.ReadAsStreamAsync();
        return new OcspResp(responseStream);
      }
      catch (Exception ex)
      {
        var msg = $"Cannot get OCSP response for url: {ocspResponderUrl}";
        _logger.Error(msg);
        throw new Exception(msg, ex);
      }
    }

    /// <summary>
    /// Validate OCSP response with Acceptance Requirements RFC 6960 3.2
    /// </summary>
    private bool validateOcspResponse(BasicOcspResp ocspResp)
    {
      var issuerCert = getOcspIssuerCert(ocspResp);

      if (issuerCert is null)
      {
        _logger.Error($"OCSP issuer certificate not found in response");
        return false;
      }

      if (!issuerCert.CanSignOcspResponses())
      {
        _logger.Error($"OCSP issuer certificate is not applicable. RFC 6960 3.2");
        return false;
      }

      if (!issuerCert.IsValidNow)
      {
        _logger.Error($"OCSP issuer certificate is not valid now. RFC 6960 3.2");
        return false;
      }

      if (!ocspResp.Verify(issuerCert.GetPublicKey()))
      {
        _logger.Error($"OCSP with invalid signature! RFC 6960 3.2");
        return false;
      }

      return true;
    }

    /// <summary>
    /// Validate OCSP response with Acceptance Requirements RFC 6960 4.2.2
    /// </summary>
    private bool validateSingleOcspResponse(SingleResp singleResp)
    {
      DateTime nowInGmt = DateTime.Now.ToUniversalTime();

      if (singleResp.NextUpdate is not null && singleResp.NextUpdate.Value < nowInGmt)
      {
        _logger.Error(
          "OCSP response is no longer valid. NextUpdate: {singleResp.NextUpdate.Value}. RFC 6960 4.2.2.1.");
        return false;
      }

      if (singleResp.ThisUpdate - nowInGmt > ocspResponseCorrectSpan)
      {
        _logger.Error(
          $"OCSP response signature is from the future. Timestamp of thisUpdate field: {singleResp.ThisUpdate}. RFC 6960 4.2.2.1.");
        return false;
      }

      return true;
    }

    private X509Certificate getOcspIssuerCert(BasicOcspResp ocspResp)
    {
      var certs = ocspResp.GetCerts()?.Cast<X509Certificate>().ToList();

      if (certs is null || certs.Count < 1)
        return null;

      var responderId = ocspResp.ResponderId.ToAsn1Object();

      if (responderId.Name is not null)
      {
        return certs.FirstOrDefault(f => f.SubjectDN.Equivalent(responderId.Name));
      }
      else
      {
        var keyHash = responderId.GetKeyHash();

        if (keyHash is null)
          return null;

        return certs.FirstOrDefault(f =>
        {
          var ki = f.GetSubjectKeyIdentifierRaw();
          return ki is not null && keyHash.SequenceEqual(ki);
        });
      }
    }

    private static string formatRevokedStatus(RevokedStatus revokedStatus)
    {
      var reason = "CrlReason: <none>";

      if (revokedStatus.HasRevocationReason)
      {
        var crlReason = CrlReason.GetInstance(new DerEnumerated(revokedStatus.RevocationReason));
        reason = crlReason.ToString();
      }

      return string.Format(Messages.certificate_revoked, revokedStatus.RevocationTime, reason);
    }
  }
}