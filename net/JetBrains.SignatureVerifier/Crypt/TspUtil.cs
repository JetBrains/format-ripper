using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;

namespace JetBrains.SignatureVerifier.Crypt
{
    //Borrowed from Bouncy for custom ValidateCertificate
    public static class TspUtil
    {
        public static void ValidateCertificate(X509Certificate cert)
        {
            /*
             * We do not really care about this
            */
             // if (cert.Version != 3)
             //     throw new ArgumentException("Certificate must have an ExtendedKeyUsage extension.");
              
            Asn1OctetString ext = cert.GetExtensionValue(X509Extensions.ExtendedKeyUsage);
            
            if (ext == null)
                throw new TspValidationException("Certificate must have an ExtendedKeyUsage extension.");

            /*
             * We do not really care about this. In real life we may encounter many absolutely random sets of KeyUsage and ExtendedKeyUsage attrs
             */
             
            // if (!cert.GetCriticalExtensionOids().Contains(X509Extensions.ExtendedKeyUsage.Id))
            //         throw new TspValidationException("Certificate must have an ExtendedKeyUsage extension marked as critical.");
             
            try
            {
                ExtendedKeyUsage extKey = ExtendedKeyUsage.GetInstance(
                    Asn1Object.FromByteArray(ext.GetOctets()));

                if (!extKey.HasKeyPurposeId(KeyPurposeID.IdKPTimeStamping) || extKey.Count != 1)
                    throw new TspValidationException("ExtendedKeyUsage not solely time stamping.");
            }
            catch (IOException)
            {
                throw new TspValidationException("cannot process ExtendedKeyUsage extension");
            }
        }
    }
}