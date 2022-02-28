using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using AttributeTable = Org.BouncyCastle.Asn1.Cms.AttributeTable;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;

namespace JetBrains.SignatureVerifier.Crypt
{
  public static class BcExt
  {
    public static string Dump(this Asn1Encodable asn1) =>
      Org.BouncyCastle.Asn1.Utilities.Asn1Dump.DumpAsString(asn1);

    public static void DumpToConsole(this Asn1Encodable asn1) => Console.WriteLine(Dump(asn1));

    public static string SN(this X509Certificate cert) =>
      ConvertToHexString(cert.SerialNumber.ToByteArrayUnsigned());

    public static string Thumbprint(this X509Certificate cert) =>
      ConvertToHexString(new SHA1Managed().ComputeHash(cert.GetEncoded()));

    public static string ConvertToHexString(byte[] data) => BitConverter.ToString(data).Replace("-", "");

    /// <summary>
    /// Extract the OCSP responder URL from certificate extension (OID 1.3.6.1.5.5.7.1.1)
    /// </summary>
    /// <param name="cert">Target certificate</param>
    /// <returns>URL-string for request an OCSP responder</returns>
    public static string GetOcspUrl(this X509Certificate cert)
    {
      var authorityInformationAccess =
        AuthorityInformationAccess.FromExtensions(cert.CertificateStructure.TbsCertificate.Extensions);

      if (authorityInformationAccess is null)
        return null;

      var ocspAccessData = authorityInformationAccess.GetAccessDescriptions()
        .FirstOrDefault(f => f.AccessMethod.Equals(OIDs.OCSP));

      if (ocspAccessData is null)
        return null;

      //rfc5280 GeneralName definition
      var url = (ocspAccessData.AccessLocation.Name as DerIA5String)?.GetString();
      return url;
    }


    /// <summary>
    /// Extract the CRL distribution urls from certificate extension (OID 2.5.29.31)
    /// See rfc5280 section-4.2.1.13
    /// </summary>
    /// <param name="cert">Target certificate</param>
    /// <returns>List of URL-strings from which CRL-files can be downloaded</returns>
    public static List<string> GetCrlDistributionUrls(this X509Certificate cert)
    {
      var res = new List<string>();
      var crldp = CrlDistPoint.FromExtensions(cert.CertificateStructure.TbsCertificate.Extensions);

      if (crldp != null)
      {
        DistributionPoint[] dps = null;
        try
        {
          dps = crldp.GetDistributionPoints();
        }
        catch (Exception e)
        {
          throw new Exception(
            "Distribution points could not be read.", e);
        }

        for (int i = 0; i < dps.Length; i++)
        {
          DistributionPointName dpn = dps[i].DistributionPointName;
          // look for URIs in fullName
          if (dpn != null)
          {
            if (dpn.PointType == DistributionPointName.FullName)
            {
              GeneralName[] genNames = GeneralNames.GetInstance(
                dpn.Name).GetNames();
              // look for an URI
              for (int j = 0; j < genNames.Length; j++)
              {
                if (genNames[j].TagNo == GeneralName.UniformResourceIdentifier)
                {
                  string location = DerIA5String.GetInstance(
                    genNames[j].Name).GetString();

                  res.Add(location);
                }
              }
            }
          }
        }
      }

      return res;
    }

    /// <summary>
    /// Check if the certificate contains any CRL distribution points
    /// </summary>
    /// <param name="cert">Target certificate</param>
    public static bool HasCrlDistributionPoints(this X509Certificate cert)
    {
      var crldp = CrlDistPoint.FromExtensions(cert.CertificateStructure.TbsCertificate.Extensions);
      return crldp != null;
    }

    public static bool IsSelfSigned([NotNull] this X509Certificate cert)
    {
      if (cert == null) throw new ArgumentNullException(nameof(cert));
      return cert.IssuerDN.Equivalent(cert.SubjectDN);
    }

    public static bool CanSignOcspResponses([NotNull] this X509Certificate cert)
    {
      if (cert == null) throw new ArgumentNullException(nameof(cert));
      return cert.GetExtendedKeyUsage().Contains(KeyPurposeID.IdKPOcspSigning.Id);
    }

    /// <summary>
    /// Extract the authorityKeyIdentifier value from certificate extension (OID 2.5.29.35)
    /// See rfc5280 section-4.2.1.1
    /// </summary>
    /// <param name="cert">Target certificate</param>
    /// <returns>Hex string of the authorityKeyIdentifier</returns>
    [CanBeNull]
    public static string GetAuthorityKeyIdentifier([NotNull] this X509Certificate cert)
    {
      if (cert == null) throw new ArgumentNullException(nameof(cert));
      var ki = AuthorityKeyIdentifier.FromExtensions(cert.CertificateStructure.TbsCertificate.Extensions);
      return ki is null ? null : BcExt.ConvertToHexString(ki.GetKeyIdentifier());
    }

    /// <summary>
    /// Extract the subjectKeyIdentifier value from certificate extension (OID 2.5.29.14)
    /// See rfc5280 section-4.2.1.2
    /// </summary>
    /// <param name="cert">Target certificate</param>
    /// <returns>Hex string of the subjectKeyIdentifier</returns>
    [CanBeNull]
    public static string GetSubjectKeyIdentifier([NotNull] this X509Certificate cert)
    {
      if (cert == null) throw new ArgumentNullException(nameof(cert));
      var ki = GetSubjectKeyIdentifierRaw(cert);
      return ki is null ? null : BcExt.ConvertToHexString(ki);
    }

    [CanBeNull]
    public static byte[] GetSubjectKeyIdentifierRaw([NotNull] this X509Certificate cert)
    {
      if (cert == null) throw new ArgumentNullException(nameof(cert));
      var ki = SubjectKeyIdentifier.FromExtensions(cert.CertificateStructure.TbsCertificate.Extensions);
      return ki is null ? null : ki.GetKeyIdentifier();
    }

    internal static string FormatId([NotNull] this X509Certificate cert)
    {
      if (cert == null) throw new ArgumentNullException(nameof(cert));
      return $"Issuer={cert.IssuerDN}; SN={cert.SN()}";
    }

    /// <summary>
    /// Extract the authorityKeyIdentifier value from CRL extension (OID 2.5.29.35)
    /// See rfc5280 section-4.2.1.1
    /// </summary>
    /// <param name="crl">Target CRL</param>
    /// <returns>Hex string of the authorityKeyIdentifier</returns>
    [CanBeNull]
    public static string GetAuthorityKeyIdentifier([NotNull] this X509Crl crl)
    {
      if (crl == null) throw new ArgumentNullException(nameof(crl));
      var ext = crl.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
      if (ext == null)
        return null;

      var ki = AuthorityKeyIdentifier.GetInstance(new X509Extension(false, ext).GetParsedValue());
      return BcExt.ConvertToHexString(ki.GetKeyIdentifier());
    }

    [CanBeNull]
    public static Asn1Encodable GetFirstAttributeValue([NotNull] this AttributeTable attrs,
      [NotNull] DerObjectIdentifier oid)
    {
      if (attrs == null) throw new ArgumentNullException(nameof(attrs));
      if (oid == null) throw new ArgumentNullException(nameof(oid));
      var attr = attrs[oid];
      return attr is not null && attr.AttrValues.Count > 0 ? attr.AttrValues[0] : null;
    }
  }
}