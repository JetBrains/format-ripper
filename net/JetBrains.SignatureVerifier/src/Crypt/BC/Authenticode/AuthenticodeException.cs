using System;
using System.Runtime.Serialization;
using Org.BouncyCastle.Cms;

namespace JetBrains.SignatureVerifier.Crypt.BC.Authenticode;

/// <summary>
/// Exception with Microsoft Authenticode structures
/// </summary>
[Serializable]
public class AuthenticodeException: CmsException
{
  public AuthenticodeException()
    : base()
  {
  }

  public AuthenticodeException(string message)
    : base(message)
  {
  }

  public AuthenticodeException(string message, Exception innerException)
    : base(message, innerException)
  {
  }

  protected AuthenticodeException(SerializationInfo info, StreamingContext context)
    : base(info, context)
  {
  }
}