using System.Text;
using JetBrains.FormatRipper.Compound;
using JetBrains.SignatureVerifier.Crypt;

namespace JetBrains.Serialization.FileInfos.Msi;

public class MsiFileInfo : FileInfo
{
  public override IFileMetaInfo FileMetaInfo { get; }
  public override SignedDataInfo SignedDataInfo { get; }

  public MsiFileInfo(CompoundFile compoundFile)
  {
    var signatureData = compoundFile.SignatureData;
    var signedMessage = SignedMessage.CreateInstance(signatureData);
    SignedDataInfo = new SignedDataInfo(signedMessage.SignedData);

    var entries = compoundFile.GetEntries();
    var specialEntries = entries.FindAll(
      entry =>
        specialValues.Contains(entry.Key.Name.Trim(new[] { '' }))
    ).Select(kv => new KeyValuePair<string, byte[]>(kv.Key.Name, kv.Value)).ToList();
    var rootEntry = entries.Find(
      entry => entry.Key.Name.Trim(new[] { '' }).Equals("Root Entry")
    );

    var digitalSignatureExData =
      entries.Find(entry => entry.Key.Name.Trim(new[] { '' }).Equals("DigitalExEntry")).Value;


    FileMetaInfo = new MsiFileMetaInfo(
      compoundFile.fileSize,
      compoundFile.HeaderMetaInfo,
      entries.Select(entry => entry.Key).ToList(),
      specialEntries,
      new List<KeyValuePair<int, byte[]>>(),
      digitalSignatureExData,
      (int)rootEntry.Key.StartingSectorLocation
    );

    return;
  }

  public static HashSet<string> specialValues = new()
  {
    new string(Encoding.Unicode.GetChars(new byte[] { 64, 72, 63, 59, 242, 67, 56, 68, 177, 69 })),
    new string(Encoding.Unicode.GetChars(new byte[] { 64, 72, 63, 63, 119, 69, 108, 68, 106, 62, 178, 68, 47, 72 })),
    "MsiDigitalSignatureEx"
  };
}