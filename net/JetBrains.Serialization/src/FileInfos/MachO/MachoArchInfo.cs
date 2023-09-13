using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos.MachO;

[JsonObject(MemberSerialization.OptIn)]
public class MachoArchInfo
{
  [JsonProperty("fileInfos")] private List<MachoFileInfo> _fileInfos = new List<MachoFileInfo>();
  [JsonProperty("headerInfo")] private FatHeaderInfo? _headerInfo;
  [JsonProperty("size")] private long _size;

  [JsonConstructor]
  public MachoArchInfo(List<MachoFileInfo> fileInfos, FatHeaderInfo? headerInfo, long size)
  {
    _fileInfos = fileInfos;
    _headerInfo = headerInfo;
    this._size = size;
  }

  public MachoArchInfo(MachOFile file)
  {
    _headerInfo = file.FatHeaderInfo;
    foreach (var fileSection in file.Sections)
    {
      _fileInfos.Add(new MachoFileInfo(fileSection));
    }

    _size = file.FileSize;
  }

  public void ModifyFile(Stream stream)
  {
    if (_headerInfo != null)
    {
      var unsignedSections =
        MachOFile.Parse(stream, MachOFile.Mode.SignatureData | MachOFile.Mode.Serialization).Sections;

      stream.Position = 0;

      if (_size > stream.Length)
      {
        stream.SetLength(_size);
      }

      stream.Position = 0;
      var headerBytes = _headerInfo.ToByteArray();
      stream.Write(headerBytes, 0, headerBytes.Length);

      foreach (var keyValuePair in unsignedSections.Zip(_fileInfos, (unsignedSection, signedFileInfo) =>
                 new KeyValuePair<MachOFile.Section, MachoFileInfo>(unsignedSection, signedFileInfo)).Reverse())
      {
        var unsignedSection = keyValuePair.Key;
        var signedFileInfo = keyValuePair.Value;
        var signedMetadata = ((MachoFileMetaInfo)signedFileInfo.FileMetaInfo).Metadata;
        if (unsignedSection.Metadata!.MachoOffset !=
            signedMetadata.MachoOffset)
        {
          stream.Position = unsignedSection.Metadata.MachoOffset;
          var data = StreamUtil.ReadBytes(stream, (int)unsignedSection.Metadata.FileSize);

          stream.Position = signedMetadata.MachoOffset;
          stream.Write(data, 0, data.Length);

          stream.Position = unsignedSection.Metadata.MachoOffset;
          stream.Write(new byte[data.Length], 0, data.Length);
        }
      }
    }


    foreach (var machoFileInfo in _fileInfos)
    {
      machoFileInfo.ModifyFile(stream);
    }
  }
}