using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509.Store;

namespace JetBrains.SignatureVerifier.Crypt.BC
{
    public class CmsSignedData
    {
        private readonly CmsProcessable signedContent;
        private SignedData signedData;
        private ContentInfo contentInfo;
        private IReadOnlyCollection<SignerInformation> signerInfoStore;
        private IX509Store certificateStore;

        public CmsSignedData(
            CmsProcessable signedContent,
            ContentInfo sigData)
        {
            this.signedContent = signedContent;
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
                if (signedData.EncapContentInfo.Content is Asn1OctetString)
                {
                    signedContent = new CmsProcessableByteArray(
                        ((Asn1OctetString) (signedData.EncapContentInfo.Content)).GetOctets());
                }
                else
                {
                    signedContent = new Pkcs7ProcessableObject(signedData.EncapContentInfo.ContentType, signedData.EncapContentInfo.Content);
                }
            }
        }

        /// <summary>Return the version number for this object.</summary>
        public int Version
        {
            get { return signedData.Version.IntValueExact; }
        }

        /**
		* return the collection of signers that are associated with the
		* signatures for the message.
		*/
        public IReadOnlyCollection<SignerInformation> GetSignerInfos()
        {
            if (signerInfoStore == null)
            {
                var signerInfos = new List<SignerInformation>();
                Asn1Set s = signedData.SignerInfos;

                foreach (object obj in s)
                {
                    SignerInfo info = SignerInfo.GetInstance(obj);
                    DerObjectIdentifier contentType = signedData.EncapContentInfo.ContentType;
                    signerInfos.Add(new SignerInformation(info, contentType, signedContent, null));
                }

                signerInfoStore = signerInfos.AsReadOnly();
            }

            return signerInfoStore;
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
    }
}