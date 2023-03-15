using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace JetBrains.SignatureVerifier.Crypt
{
  class CustomPkixBuilderParameters : PkixBuilderParameters
  {
    [NotNull] private readonly IX509Store _intermediateCertsStore;
    [NotNull] private readonly X509CertStoreSelector _primaryCertHolder;

    public CustomPkixBuilderParameters([NotNull] HashSet rootCertificates,
      [NotNull] IX509Store intermediateCertsStore,
      [NotNull] X509CertStoreSelector primaryCertHolder,
      DateTime? signValidationTime)
      : base(rootCertificates, primaryCertHolder)
    {
      if (rootCertificates == null) throw new ArgumentNullException(nameof(rootCertificates));
      if (intermediateCertsStore == null) throw new ArgumentNullException(nameof(intermediateCertsStore));
      if (primaryCertHolder == null) throw new ArgumentNullException(nameof(primaryCertHolder));

      _intermediateCertsStore = intermediateCertsStore;
      _primaryCertHolder = primaryCertHolder;
      ValidityModel = ChainValidityModel;
      Date = signValidationTime.HasValue ? new DateTimeObject(signValidationTime.Value) : null;
      IsRevocationEnabled = false;
      AddStore(intermediateCertsStore);
    }

    /// <summary>
    /// Prepare CRLs for all certificates
    /// </summary>
    /// <param name="crlProvider">CrlProvider for CRLs consume</param>
    /// <returns>
    /// True if CRLs successfully added to the params, False if CRLs can not be used (and OCSP is considered)
    /// </returns>
    public async Task<bool> PrepareCrls([NotNull] CrlProvider crlProvider)
    {
      if (crlProvider == null) throw new ArgumentNullException(nameof(crlProvider));

      var certs = _intermediateCertsStore.GetMatches(null).Cast<X509Certificate>().ToList();
      certs.Add(_primaryCertHolder.Certificate);
      certs.RemoveAll(cert => cert.IsSelfSigned());
      var allCerts = certs.Distinct(new X509CertificateEquComparer()).ToList();
      var allCrls = await getCrlsForCertsAsync(crlProvider, allCerts);

      if (allCrls is null)
        return true;

      var crlStore = getCrlStore(allCrls);
      AddStore(crlStore);
      IsRevocationEnabled = true;

      return false;
    }

    public override IList GetCertPathCheckers()
    {
      var cpc = new CustomPkixCertPathChecker();
      return new List<CustomPkixCertPathChecker> { cpc };
    }

    private async Task<List<X509Crl>> getCrlsForCertsAsync(CrlProvider crlProvider, List<X509Certificate> allCerts)
    {
      var allCrls = new List<X509Crl>();

      foreach (X509Certificate cert in allCerts)
      {
        var crls = (await crlProvider.GetCrlsAsync(cert))
          .Where(crl => crl.ThisUpdate.CompareTo(cert.NotAfter) < 0)
          .ToList();

        //if any certificate won't check with CRL - reject others

        if (crls.Count == 0)
          return null;

        allCrls.AddRange(crls);
      }

      allCrls = allCrls.Distinct(new X509CrlEquComparer()).ToList();
      return allCrls;
    }


    private IX509Store getCrlStore(List<X509Crl> crls)
    {
      IX509Store crlStore = X509StoreFactory.Create(
        "CRL/Collection",
        new X509CollectionStoreParameters(crls));

      return crlStore;
    }
  }
}