using JetBrains.SignatureVerifier.Crypt.BC;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos;

/*
 * TODO: This class should be replaced by SignedDataInfo:IEncodableInfo from net-serialization-dataholders.
 */
[JsonObject(MemberSerialization.OptIn)]
public class SignedDataInfo
{
  [JsonProperty("data")] private CmsSignedData _data;

  [JsonConstructor]
  public SignedDataInfo(CmsSignedData signedData)
  {
    _data = signedData;
  }

  public byte[] ToSignature(string encoding = "DER") => _data.GetEncoded(encoding);
}