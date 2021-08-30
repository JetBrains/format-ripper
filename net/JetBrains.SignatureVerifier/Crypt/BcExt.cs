using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;

namespace JetBrains.SignatureVerifier.Crypt
{
    public static class BcExt
    {
        public static string Dump(this Asn1Encodable asn1) =>
            Org.BouncyCastle.Asn1.Utilities.Asn1Dump.DumpAsString(asn1);

        public static void DumpToConsole(this Asn1Encodable asn1) => Console.WriteLine(Dump(asn1));

        public static string SN(this Org.BouncyCastle.X509.X509Certificate cert) =>
            ConvertToHexString(cert.SerialNumber.ToByteArrayUnsigned());

        public static string ConvertToHexString(byte[] data) => BitConverter.ToString(data).Replace("-", "");

        /// <summary>
        /// Extract the CRL distribution urls from certificate extension (OID 2.5.29.31) 
        /// See rfc5280 section-4.2.1.13 
        /// </summary>
        /// <param name="cert">Target certificate</param>
        /// <returns>List of URL-strings from which CRL-files can be downloaded</returns> 
        public static List<string> GetCrlDistributionUrls(this Org.BouncyCastle.X509.X509Certificate cert)
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
        /// Extract the authorityKeyIdentifier value from certificate extension (OID 2.5.29.35)
        /// See rfc5280 section-4.2.1.1 
        /// </summary>
        /// <param name="cert">Target certificate</param>
        /// <returns>Hex string of the authorityKeyIdentifier</returns>
        public static string GetAuthorityKeyIdentifier(this Org.BouncyCastle.X509.X509Certificate cert)
        {
            var aki = AuthorityKeyIdentifier.FromExtensions(cert.CertificateStructure.TbsCertificate.Extensions);
            return aki is null ? null : BcExt.ConvertToHexString(aki.GetKeyIdentifier());
        }
    }
}