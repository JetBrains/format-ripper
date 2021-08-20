using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace JetBrains.SignatureVerifier.Crypt.BC
{
    /// <summary>
    /// Partially borrowed from Org.BouncyCastle.Cms.CmsSignedHelper and Org.BouncyCastle.Cms.CmsEnvelopedHelper
    /// </summary>
    public static class Helper
    {
        private static readonly Dictionary<string, string> digestAlgs = new Dictionary<string, string>();
        private static readonly Dictionary<string, string> encryptionAlgs = new Dictionary<string, string>();
        private static readonly Dictionary<string, string[]> digestAliases = new Dictionary<string, string[]>();

        private static void AddEntries(DerObjectIdentifier oid, string digest, string encryption)
        {
            string alias = oid.Id;
            digestAlgs.Add(alias, digest);
            encryptionAlgs.Add(alias, encryption);
        }

        static Helper()
        {
            AddEntries(NistObjectIdentifiers.DsaWithSha224, "SHA224", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha256, "SHA256", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha384, "SHA384", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha512, "SHA512", "DSA");
            AddEntries(OiwObjectIdentifiers.DsaWithSha1, "SHA1", "DSA");
            AddEntries(OiwObjectIdentifiers.MD4WithRsa, "MD4", "RSA");
            AddEntries(OiwObjectIdentifiers.MD4WithRsaEncryption, "MD4", "RSA");
            AddEntries(OiwObjectIdentifiers.MD5WithRsa, "MD5", "RSA");
            AddEntries(OiwObjectIdentifiers.Sha1WithRsa, "SHA1", "RSA");
            AddEntries(PkcsObjectIdentifiers.MD2WithRsaEncryption, "MD2", "RSA");
            AddEntries(PkcsObjectIdentifiers.MD4WithRsaEncryption, "MD4", "RSA");
            AddEntries(PkcsObjectIdentifiers.MD5WithRsaEncryption, "MD5", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha1WithRsaEncryption, "SHA1", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha224WithRsaEncryption, "SHA224", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha256WithRsaEncryption, "SHA256", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha384WithRsaEncryption, "SHA384", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha512WithRsaEncryption, "SHA512", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha512_224WithRSAEncryption, "SHA512(224)", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha512_256WithRSAEncryption, "SHA512(256)", "RSA");
            AddEntries(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224, "SHA3-224", "RSA");
            AddEntries(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256, "SHA3-256", "RSA");
            AddEntries(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384, "SHA3-384", "RSA");
            AddEntries(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512, "SHA3-512", "RSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha1, "SHA1", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha224, "SHA224", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha256, "SHA256", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha384, "SHA384", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha512, "SHA512", "ECDSA");
            AddEntries(X9ObjectIdentifiers.IdDsaWithSha1, "SHA1", "DSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, "SHA1", "RSA");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, "SHA256", "RSA");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_PSS_SHA_1, "SHA1", "RSAandMGF1");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_PSS_SHA_256, "SHA256", "RSAandMGF1");
            
            encryptionAlgs.Add(X9ObjectIdentifiers.IdDsa.Id, "DSA");
            encryptionAlgs.Add(PkcsObjectIdentifiers.RsaEncryption.Id, "RSA");
            encryptionAlgs.Add(TeleTrusTObjectIdentifiers.TeleTrusTRsaSignatureAlgorithm.Id, "RSA");
            encryptionAlgs.Add(X509ObjectIdentifiers.IdEARsa.Id, "RSA");
            encryptionAlgs.Add(CmsSignedGenerator.EncryptionRsaPss, "RSAandMGF1");

            digestAlgs.Add(PkcsObjectIdentifiers.MD2.Id, "MD2");
            digestAlgs.Add(PkcsObjectIdentifiers.MD4.Id, "MD4");
            digestAlgs.Add(PkcsObjectIdentifiers.MD5.Id, "MD5");
            digestAlgs.Add(OiwObjectIdentifiers.IdSha1.Id, "SHA1");
            digestAlgs.Add(NistObjectIdentifiers.IdSha224.Id, "SHA224");
            digestAlgs.Add(NistObjectIdentifiers.IdSha256.Id, "SHA256");
            digestAlgs.Add(NistObjectIdentifiers.IdSha384.Id, "SHA384");
            digestAlgs.Add(NistObjectIdentifiers.IdSha512.Id, "SHA512");
            digestAlgs.Add(NistObjectIdentifiers.IdSha512_224.Id, "SHA512(224)");
            digestAlgs.Add(NistObjectIdentifiers.IdSha512_256.Id, "SHA512(256)");
            digestAlgs.Add(NistObjectIdentifiers.IdSha3_224.Id, "SHA3-224");
            digestAlgs.Add(NistObjectIdentifiers.IdSha3_256.Id, "SHA3-256");
            digestAlgs.Add(NistObjectIdentifiers.IdSha3_384.Id, "SHA3-384");
            digestAlgs.Add(NistObjectIdentifiers.IdSha3_512.Id, "SHA3-512");
            
            digestAliases.Add("SHA1", new string[] { "SHA-1" });
            digestAliases.Add("SHA224", new string[] { "SHA-224" });
            digestAliases.Add("SHA256", new string[] { "SHA-256" });
            digestAliases.Add("SHA384", new string[] { "SHA-384" });
            digestAliases.Add("SHA512", new string[] { "SHA-512" });
        }
        
        /**
        * Return the digest algorithm using one of the standard JCA string
        * representations rather than the algorithm identifier (if possible).
        */
        internal static string GetDigestAlgName(string digestAlgOid)
        {
            string algName = (string)digestAlgs[digestAlgOid];

            if (algName != null)
            {
                return algName;
            }

            return digestAlgOid;
        }

        internal static string[] GetDigestAliases(
            string algName)
        {
            string[] aliases = (string[]) digestAliases[algName];

            return aliases == null ? new string[0] : (string[]) aliases.Clone();
        }

        /**
        * Return the digest encryption algorithm using one of the standard
        * JCA string representations rather than the algorithm identifier (if
        * possible).
        */
        internal static string GetEncryptionAlgName(
            string encryptionAlgOid)
        {
            string algName = (string) encryptionAlgs[encryptionAlgOid];

            if (algName != null)
            {
                return algName;
            }

            return encryptionAlgOid;
        }
        
        internal static IDigest GetDigestInstance(
            string algorithm)
        {
            try
            {
                return DigestUtilities.GetDigest(algorithm);
            }
            catch (SecurityUtilityException e)
            {
                // This is probably superfluous on C#, since no provider infrastructure,
                // assuming DigestUtilities already knows all the aliases
                foreach (string alias in GetDigestAliases(algorithm))
                {
                    try { return DigestUtilities.GetDigest(alias); }
                    catch (SecurityUtilityException) {}
                }
                throw e;
            }
        }
        
        internal static ISigner GetSignatureInstance(
            string algorithm)
        {
            return SignerUtilities.GetSigner(algorithm);
        }

        internal static IBufferedCipher CreateAsymmetricCipher(
            string encryptionOid)
        {
            string asymName = GetAsymmetricEncryptionAlgName(encryptionOid);
            if (!asymName.Equals(encryptionOid))
            {
                try
                {
                    return CipherUtilities.GetCipher(asymName);
                }
                catch (SecurityUtilityException)
                {
                    // Ignore
                }
            }
            return CipherUtilities.GetCipher(encryptionOid);
        }
        
        static internal IX509Store CreateCertificateStore(
            string	type,
            Asn1Set	certSet)
        {
            var certs = new List<X509Certificate>();

            if (certSet != null)
            {
                AddCertsFromSet(certs, certSet);
            }

            try
            {
                return X509StoreFactory.Create(
                    "Certificate/" + type,
                    new X509CollectionStoreParameters(certs));
            }
            catch (ArgumentException e)
            {
                throw new CmsException("can't setup the X509Store", e);
            }
        }
        
        private  static  void AddCertsFromSet(
            List<X509Certificate>	certs,
            Asn1Set	certSet)
        {
            X509CertificateParser cf = new X509CertificateParser();

            foreach (Asn1Encodable ae in certSet)
            {
                try
                {
                    Asn1Object obj = ae.ToAsn1Object();

                    if (obj is Asn1Sequence)
                    {
                        // TODO Build certificate directly from sequence?
                        certs.Add(cf.ReadCertificate(obj.GetEncoded()));
                    }
                }
                catch (Exception ex)
                {
                    throw new CmsException("can't re-encode certificate!", ex);
                }
            }
        }

        private static string GetAsymmetricEncryptionAlgName(
            string encryptionAlgOid)
        {
            if (PkcsObjectIdentifiers.RsaEncryption.Id.Equals(encryptionAlgOid))
            {
                return "RSA/ECB/PKCS1Padding";
            }

            return encryptionAlgOid;
        }
    }
}