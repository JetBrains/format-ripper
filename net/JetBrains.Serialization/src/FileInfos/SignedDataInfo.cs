using JetBrains.SignatureVerifier.Crypt.BC;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos;

/*
 * TODO: This class should be replaced by SignedDataInfo:IEncodableInfo from net-serialization-dataholders.
 */
[JsonObject(MemberSerialization.OptIn)]
public class SignedDataInfo
{
  // We store both DER and BER data only for serialization to work,
  // this will not be an issue in SignedDataInfo:IEncodableInfo from net-serialization-dataholders
  [JsonProperty("dataDer")] private byte[] _dataDer;
  [JsonProperty("dataBer")] private byte[] _dataBer;

  [JsonConstructor]
  public SignedDataInfo(byte[] dataDer, byte[] dataBer)
  {
    _dataDer = dataDer;
    _dataBer = dataBer;
  }


  public SignedDataInfo(CmsSignedData signedData)
  {
    _dataDer = signedData.GetEncoded("DER");
    _dataBer = signedData.GetEncoded("BER");
  }

  public byte[] ToSignature(string encoding = "DER")
  {
    switch (encoding)
    {
      case "DER":
        return _dataDer;
      default:
        return _dataBer;
    }
  }
}