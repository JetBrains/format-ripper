using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Org.BouncyCastle.X509;

namespace JetBrains.SignatureVerifier.Crypt
{
  public class CrlProvider
  {
    private readonly CrlCacheFileSystem _crlCash;
    private readonly X509CrlParser _crlParser = new X509CrlParser();

    public CrlProvider([NotNull] CrlCacheFileSystem crlCash)
    {
      _crlCash = crlCash ?? throw new ArgumentNullException(nameof(crlCash));
    }

    public async Task<ReadOnlyCollection<X509Crl>> GetCrlsAsync(X509Certificate cert)
    {
      var crlId = cert.GetAuthorityKeyIdentifier();
      var res = _crlCash.GetCrls(crlId);

      if (res is not null && res.Count != 0 && !crlsIsOutDate(res))
        return res;

      var urls = cert.GetCrlDistributionUrls();
      var crlsData = await downloadCrlsAsync(urls);

      //We have to filter out CRLs with an empty NextUpdate field
      //See https://github.com/bcgit/bc-csharp/issues/315
      var crls = crlsData.Select(s => new { Crl = _crlParser.ReadCrl(s), Data = s })
        .Where(w => w.Crl.NextUpdate is not null).ToList();
      _crlCash.UpdateCrls(crlId, crls.Select(s => s.Data).ToList());
      return crls.Select(s => s.Crl).ToList().AsReadOnly();
    }

    private async Task<List<byte[]>> downloadCrlsAsync(List<string> urls)
    {
      var res = new List<byte[]>();

      foreach (var url in urls)
      {
        using var httpClient = new HttpClient();
        try
        {
          var data = await httpClient.GetByteArrayAsync(url).ConfigureAwait(false);
          res.Add(data);
        }
        catch (HttpRequestException ex)
        {
          throw new Exception($"Cannot download CRL from: {url}", ex);
        }
      }

      return res;
    }

    private bool crlsIsOutDate(ReadOnlyCollection<X509Crl> crls)
    {
      var now = DateTime.Now;
      return crls.Any(a => a.NextUpdate.Value.Ticks <= now.Ticks);
    }
  }
}