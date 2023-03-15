using System;
using System.Net.Http;
using System.Threading.Tasks;
using JetBrains.Annotations;

namespace JetBrains.SignatureVerifier.Crypt
{
  public class CrlSource
  {
    public virtual async Task<byte[]> GetCrlAsync([NotNull] string url)
    {
      if (url == null) throw new ArgumentNullException(nameof(url));

      using var httpClient = new HttpClient();
      try
      {
        return await httpClient.GetByteArrayAsync(url).ConfigureAwait(false);
      }
      catch (HttpRequestException ex)
      {
        throw new Exception($"Cannot download CRL from: {url}", ex);
      }
    }
  }
}