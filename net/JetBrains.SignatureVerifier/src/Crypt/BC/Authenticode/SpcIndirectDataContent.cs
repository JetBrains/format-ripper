using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.SignatureVerifier.Crypt.BC.Authenticode;

/// <summary>
/// Class that represents Microsoft Authenticode structure SpcIndirectDataContent
/// </summary>
public class SpcIndirectDataContent
{
  public DigestInfo DigestInfo { get; private set; }

  public static SpcIndirectDataContent GetInstance(object obj)
  {
    if (obj is SpcIndirectDataContent)
      return (SpcIndirectDataContent)obj;
    if (obj == null)
      return null;
    return new SpcIndirectDataContent(Asn1Sequence.GetInstance(obj));
  }

  private SpcIndirectDataContent(Asn1Sequence seq)
  {
    if (seq.Count != 2)
      throw new ArgumentException($"Wrong number of elements in sequence. Expected: 2, got: ${seq.Count}");

    // Skipping SpcAttributeTypeAndOptionalValue
    DigestInfo = DigestInfo.GetInstance(seq[1]);
  }
}

