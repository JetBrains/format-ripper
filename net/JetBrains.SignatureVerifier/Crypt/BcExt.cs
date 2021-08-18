using System;
using Org.BouncyCastle.Asn1;

namespace JetBrains.SignatureVerifier.Crypt
{
    public static class BcExt
    {
        public static string Dump(this Asn1Encodable asn1) => Org.BouncyCastle.Asn1.Utilities.Asn1Dump.DumpAsString(asn1);
        public static void DumpToConsole(this Asn1Encodable asn1) => Console.WriteLine(Dump(asn1));

        public static string SN(this Org.BouncyCastle.X509.X509Certificate cert) =>
            ConvertToHexString(cert.SerialNumber.ToByteArrayUnsigned());
        
        public static string ConvertToHexString(byte[] data) => BitConverter.ToString(data).Replace("-", "");
    }
}