using System;
using System.Diagnostics;
using System.Linq;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.SignatureVerifier
{
    public static class OIDs
    {
        public static readonly DerObjectIdentifier SPC_INDIRECT_DATA_OBJ_ID = new("1.3.6.1.4.1.311.2.1.4");
    }

    public class SpcIndirectDataContent
    {
        private byte[] _signedContent;
        private readonly Asn1Encodable _content;

        /// <summary>
        /// PE hash alg & data
        /// </summary>
        public DigestInfo MessageDigest { get; }

        /// <summary>
        /// All content for sign
        /// </summary>
        public byte[] SignedContent => _signedContent ??= getSignedContent();

        private byte[] getSignedContent()
        {
            var data = _content.GetEncoded();

            if (data.Length < 4)
                return null;

            //skip header
            var headerLen = getHeaderLen(data);
            var res = new byte[data.Length - headerLen];
            Array.Copy(data, headerLen, res, 0, res.Length);
            return res;
        }

        private int getHeaderLen(byte[] data)
        {
            var seq = Asn1Object.FromByteArray(data) as Asn1Sequence;
            Debug.Assert(seq != null, nameof(seq) + " != null");
            var len = seq.ToArray().Sum(s => s.GetEncoded().Length);
            return data.Length - len;
        }

        public SpcIndirectDataContent([NotNull] ContentInfo contentInfo)
        {
            if (contentInfo == null) throw new ArgumentNullException(nameof(contentInfo));

            if (!contentInfo.ContentType.Equals(OIDs.SPC_INDIRECT_DATA_OBJ_ID))
                return;

            _content = contentInfo.Content;
            var seq = Asn1Sequence.GetInstance(contentInfo.Content);

            //skip first item which is spcPEImageData 
            if (seq?.Count > 1)
                MessageDigest = DigestInfo.GetInstance(seq[1]);
        }
    }
}