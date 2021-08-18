using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace JetBrains.SignatureVerifier.Crypt
{
    class CustomPkixCertPathChecker: PkixCertPathChecker
    {
        public override void Init(bool forward)
        {
        }

        public override bool IsForwardCheckingSupported()
        {
            throw new NotSupportedException();
        }

        public override ISet GetSupportedExtensions()
        {
            throw new NotSupportedException();
        }

        public override void Check(X509Certificate cert, ISet unresolvedCritExts)
        {
            unresolvedCritExts.Remove(OIDs.EXTENDED_KEY_USAGE.Id);
        }
    }
    
    class CustomPkixBuilderParameters : PkixBuilderParameters
    {
        public CustomPkixBuilderParameters(HashSet rootCertificates, X509CertStoreSelector holder) 
            : base(rootCertificates,holder)
        {
             
        }

        public override IList GetCertPathCheckers()
        {
            var cpc = new CustomPkixCertPathChecker();
            return new List<CustomPkixCertPathChecker> {cpc};
        }
    }
}