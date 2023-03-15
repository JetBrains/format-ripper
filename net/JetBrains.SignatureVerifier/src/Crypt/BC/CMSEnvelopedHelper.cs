using System;
using System.Collections;
using JetBrains.SignatureVerifier.Crypt.BC.Compat;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace JetBrains.SignatureVerifier.Crypt.BC
{
  class CmsEnvelopedHelper
  {
    internal static readonly CmsEnvelopedHelper Instance = new CmsEnvelopedHelper();

    private static readonly IDictionary KeySizes = Platform.CreateHashtable();
    private static readonly IDictionary BaseCipherNames = Platform.CreateHashtable();

    static CmsEnvelopedHelper()
    {
      KeySizes.Add(CmsEnvelopedGenerator.DesEde3Cbc, 192);
      KeySizes.Add(CmsEnvelopedGenerator.Aes128Cbc, 128);
      KeySizes.Add(CmsEnvelopedGenerator.Aes192Cbc, 192);
      KeySizes.Add(CmsEnvelopedGenerator.Aes256Cbc, 256);

      BaseCipherNames.Add(CmsEnvelopedGenerator.DesEde3Cbc, "DESEDE");
      BaseCipherNames.Add(CmsEnvelopedGenerator.Aes128Cbc, "AES");
      BaseCipherNames.Add(CmsEnvelopedGenerator.Aes192Cbc, "AES");
      BaseCipherNames.Add(CmsEnvelopedGenerator.Aes256Cbc, "AES");
    }

    private string GetAsymmetricEncryptionAlgName(
      string encryptionAlgOid)
    {
      if (PkcsObjectIdentifiers.RsaEncryption.Id.Equals(encryptionAlgOid))
      {
        return "RSA/ECB/PKCS1Padding";
      }

      return encryptionAlgOid;
    }

    internal IBufferedCipher CreateAsymmetricCipher(
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

    internal IWrapper CreateWrapper(
      string encryptionOid)
    {
      try
      {
        return WrapperUtilities.GetWrapper(encryptionOid);
      }
      catch (SecurityUtilityException)
      {
        return WrapperUtilities.GetWrapper(GetAsymmetricEncryptionAlgName(encryptionOid));
      }
    }

    internal string GetRfc3211WrapperName(
      string oid)
    {
      if (oid == null)
        throw new ArgumentNullException("oid");

      string alg = (string)BaseCipherNames[oid];

      if (alg == null)
        throw new ArgumentException("no name for " + oid, "oid");

      return alg + "RFC3211Wrap";
    }

    internal int GetKeySize(
      string oid)
    {
      if (!KeySizes.Contains(oid))
      {
        throw new ArgumentException("no keysize for " + oid, "oid");
      }

      return (int)KeySizes[oid];
    }
  }
}