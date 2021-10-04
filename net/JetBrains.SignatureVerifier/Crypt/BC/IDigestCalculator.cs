using System;

namespace JetBrains.SignatureVerifier.BouncyCastle.Cms
{
  internal interface IDigestCalculator
  {
    byte[] GetDigest();
  }
}