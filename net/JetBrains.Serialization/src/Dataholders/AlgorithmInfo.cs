using System;
using System.Collections.Generic;
using JetBrains.Annotations;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class AlgorithmInfo : IEncodableInfo
{
  [JsonProperty("name")] private String _name;

  [JsonProperty("additionalValue")] private IEncodableInfo? _additionalValue = null;

  [JsonProperty("algorithmIdentifier")] private TextualInfo _algorithmIdentifier;

  [JsonConstructor]
  public AlgorithmInfo(string name, TextualInfo algorithmIdentifier)
  {
    _name = name;
    _algorithmIdentifier = algorithmIdentifier;
  }

  public AlgorithmInfo(AlgorithmIdentifier signatureAlgorithm)
  {
    _name = SerializationUtils.AlgorithmNameFromId(signatureAlgorithm.Algorithm);
    _additionalValue = signatureAlgorithm.Parameters?.ToAsn1Object()?.ToEncodableInfo();
    _algorithmIdentifier = TextualInfo.GetInstance(signatureAlgorithm.Algorithm);
  }

  public Asn1Encodable ToPrimitive() => new List<IEncodableInfo?> { _algorithmIdentifier, _additionalValue }
    .ToPrimitiveDerSequence()
    .ToAsn1Object();
}