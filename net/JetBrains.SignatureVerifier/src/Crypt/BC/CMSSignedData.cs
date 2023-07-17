using System;
using System.Collections;
using JetBrains.SignatureVerifier.Crypt.BC.Compat;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509.Store;

namespace JetBrains.SignatureVerifier.Crypt.BC
{
  /**
  * general class for handling a pkcs7-signature message.
  *
  * A simple example of usage - note, in the example below the validity of
  * the certificate isn't verified, just the fact that one of the certs
  * matches the given signer...
  *
  * <pre>
  *  IX509Store              certs = s.GetCertificates();
  *  SignerInformationStore  signers = s.GetSignerInfos();
  *
  *  foreach (SignerInformation signer in signers.GetSigners())
  *  {
  *      ArrayList       certList = new ArrayList(certs.GetMatches(signer.SignerID));
  *      X509Certificate cert = (X509Certificate) certList[0];
  *
  *      if (signer.Verify(cert.GetPublicKey()))
  *      {
  *          verified++;
  *      }
  *  }
  * </pre>
  */
  public class CmsSignedData
  {
    private static readonly CmsSignedHelper Helper = CmsSignedHelper.Instance;

    private readonly CmsProcessable signedContent;
    private SignedData signedData;
    private ContentInfo contentInfo;
    private SignerInformationStore signerInfoStore;
    private IX509Store attrCertStore;
    private IX509Store certificateStore;
    private IX509Store crlStore;
    private IDictionary hashes;

    private CmsSignedData(
      CmsSignedData c)
    {
      this.signedData = c.signedData;
      this.contentInfo = c.contentInfo;
      this.signedContent = c.signedContent;
      this.signerInfoStore = c.signerInfoStore;
    }

    public CmsSignedData(
      CmsProcessable signedContent,
      ContentInfo sigData)
    {
      this.signedContent = signedContent;
      this.contentInfo = sigData;
      this.signedData = SignedData.GetInstance(contentInfo.Content);
    }

    public CmsSignedData(
      IDictionary hashes,
      ContentInfo sigData)
    {
      this.hashes = hashes;
      this.contentInfo = sigData;
      this.signedData = SignedData.GetInstance(contentInfo.Content);
    }

    public CmsSignedData(
      ContentInfo sigData)
    {
      this.contentInfo = sigData;
      this.signedData = SignedData.GetInstance(contentInfo.Content);

      //
      // this can happen if the signed message is sent simply to send a
      // certificate chain.
      //
      if (signedData.EncapContentInfo.Content != null)
      {
        // https://github.com/bcgit/bc-csharp/issues/310

        if (signedData.EncapContentInfo.Content is Asn1OctetString)
        {
          signedContent = new CmsProcessableByteArray(
            ((Asn1OctetString)(signedData.EncapContentInfo.Content)).GetOctets());
        }
        else
        {
          signedContent = new Pkcs7ProcessableObject(signedData.EncapContentInfo.ContentType,
            signedData.EncapContentInfo.Content);
        }
      }
//			else
//			{
//				this.signedContent = null;
//			}
    }

    /// <summary>Return the version number for this object.</summary>
    public int Version
    {
      get { return signedData.Version.IntValueExact; }
    }

    internal IX509Store GetCertificates()
    {
      return Helper.GetCertificates(signedData.Certificates);
    }

    /**
    * return the collection of signers that are associated with the
    * signatures for the message.
    */
    public SignerInformationStore GetSignerInfos()
    {
      if (signerInfoStore == null)
      {
        IList signerInfos = Platform.CreateArrayList();
        Asn1Set s = signedData.SignerInfos;

        foreach (object obj in s)
        {
          SignerInfo info = SignerInfo.GetInstance(obj);
          DerObjectIdentifier contentType = signedData.EncapContentInfo.ContentType;

          if (hashes == null)
          {
            signerInfos.Add(new SignerInformation(info, contentType, signedContent, null));
          }
          else
          {
            byte[] hash = (byte[])hashes[info.DigestAlgorithm.Algorithm.Id];

            signerInfos.Add(new SignerInformation(info, contentType, null, new BaseDigestCalculator(hash)));
          }
        }

        signerInfoStore = new SignerInformationStore(signerInfos);
      }

      return signerInfoStore;
    }

    /**
     * return a X509Store containing the attribute certificates, if any, contained
     * in this message.
     *
     * @param type type of store to create
     * @return a store of attribute certificates
     * @exception NoSuchStoreException if the store type isn't available.
     * @exception CmsException if a general exception prevents creation of the X509Store
     */
    public IX509Store GetAttributeCertificates(
      string type)
    {
      if (attrCertStore == null)
      {
        attrCertStore = Helper.CreateAttributeStore(type, signedData.Certificates);
      }

      return attrCertStore;
    }

    /**
     * return a X509Store containing the public key certificates, if any, contained
     * in this message.
     *
     * @param type type of store to create
     * @return a store of public key certificates
     * @exception NoSuchStoreException if the store type isn't available.
     * @exception CmsException if a general exception prevents creation of the X509Store
     */
    public IX509Store GetCertificates(
      string type)
    {
      if (certificateStore == null)
      {
        certificateStore = Helper.CreateCertificateStore(type, signedData.Certificates);
      }

      return certificateStore;
    }

    /**
    * return a X509Store containing CRLs, if any, contained
    * in this message.
    *
    * @param type type of store to create
    * @return a store of CRLs
    * @exception NoSuchStoreException if the store type isn't available.
    * @exception CmsException if a general exception prevents creation of the X509Store
    */
    public IX509Store GetCrls(
      string type)
    {
      if (crlStore == null)
      {
        crlStore = Helper.CreateCrlStore(type, signedData.CRLs);
      }

      return crlStore;
    }

    [Obsolete("Use 'SignedContentType' property instead.")]
    public string SignedContentTypeOid
    {
      get { return signedData.EncapContentInfo.ContentType.Id; }
    }

    /// <summary>
    /// Return the <c>DerObjectIdentifier</c> associated with the encapsulated
    /// content info structure carried in the signed data.
    /// </summary>
    public DerObjectIdentifier SignedContentType
    {
      get { return signedData.EncapContentInfo.ContentType; }
    }

    public CmsProcessable SignedContent
    {
      get { return signedContent; }
    }

    public SignedData SignedData
    {
      get { return signedData; }
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo ContentInfo
    {
      get { return contentInfo; }
    }

    /**
    * return the ASN.1 encoded representation of this object.
    */
    public byte[] GetEncoded()
    {
      return contentInfo.GetEncoded();
    }

    /**
         * return the ASN.1 encoded representation of this object using the specified encoding.
         *
         * @param encoding the ASN.1 encoding format to use ("BER" or "DER").
         */
    public byte[] GetEncoded(string encoding)
    {
      return contentInfo.GetEncoded(encoding);
    }

    /**
    * Replace the signerinformation store associated with this
    * CmsSignedData object with the new one passed in. You would
    * probably only want to do this if you wanted to change the unsigned
    * attributes associated with a signer, or perhaps delete one.
    *
    * @param signedData the signed data object to be used as a base.
    * @param signerInformationStore the new signer information store to use.
    * @return a new signed data object.
    */
    public static CmsSignedData ReplaceSigners(
      CmsSignedData signedData,
      SignerInformationStore signerInformationStore)
    {
      //
      // copy
      //
      CmsSignedData cms = new CmsSignedData(signedData);

      //
      // replace the store
      //
      cms.signerInfoStore = signerInformationStore;

      //
      // replace the signers in the SignedData object
      //
      Asn1EncodableVector digestAlgs = new Asn1EncodableVector();
      Asn1EncodableVector vec = new Asn1EncodableVector();

      foreach (SignerInformation signer in signerInformationStore.GetSigners())
      {
        digestAlgs.Add(Helper.FixAlgID(signer.DigestAlgorithmID));
        vec.Add(signer.ToSignerInfo());
      }

      Asn1Set digests = new DerSet(digestAlgs);
      Asn1Set signers = new DerSet(vec);
      Asn1Sequence sD = (Asn1Sequence)signedData.signedData.ToAsn1Object();

      //
      // signers are the last item in the sequence.
      //
      vec = new Asn1EncodableVector(
        sD[0], // version
        digests);

      for (int i = 2; i != sD.Count - 1; i++)
      {
        vec.Add(sD[i]);
      }

      vec.Add(signers);

      cms.signedData = SignedData.GetInstance(new BerSequence(vec));

      //
      // replace the contentInfo with the new one
      //
      cms.contentInfo = new ContentInfo(cms.contentInfo.ContentType, cms.signedData);

      return cms;
    }
  }
}