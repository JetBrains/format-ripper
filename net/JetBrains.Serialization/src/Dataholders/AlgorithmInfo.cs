using System;
using System.Collections.Generic;
using JetBrains.Annotations;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class AlgorithmInfo : IEncodableInfo
{
  private String _name;
  [CanBeNull] private IEncodableInfo _additionalValue = null;
  private TextualInfo _algorithmIdentifier;

  public AlgorithmInfo(AlgorithmIdentifier signatureAlgorithm)
  {
    _name = SerializationUtils.AlgorithmNameFromId(signatureAlgorithm.Algorithm);
    _additionalValue = signatureAlgorithm.Parameters?.ToAsn1Object()?.ToEncodableInfo();
    _algorithmIdentifier = TextualInfo.GetInstance(signatureAlgorithm.Algorithm);
  }

  public Asn1Encodable ToPrimitive() => new List<IEncodableInfo> { _algorithmIdentifier, _additionalValue }
    .ToPrimitiveList().ToDerSequence()
    .ToAsn1Object();
}