using System;
using System.Collections.Generic;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace JetBrains.SignatureVerifier.Crypt
{
  class CustomPkixCertPathChecker : PkixCertPathChecker
  {
    public override void Init(bool forward)
    {
    }

    public override bool IsForwardCheckingSupported()
    {
      throw new NotSupportedException();
    }

    public override ISet<string> GetSupportedExtensions()
    {
      throw new NotImplementedException();
    }

    public override void Check(X509Certificate cert, ISet<string> unresolvedCritExts)
    {
      unresolvedCritExts.Remove(OIDs.EXTENDED_KEY_USAGE.Id);
      unresolvedCritExts.Remove(OIDs.APPLE_CERTIFICATE_EXTENSION_CODE_SIGNING.Id);
      unresolvedCritExts.Remove(OIDs.APPLE_CERTIFICATE_EXTENSION_KEXT_SIGNING.Id);
    }
  }
}