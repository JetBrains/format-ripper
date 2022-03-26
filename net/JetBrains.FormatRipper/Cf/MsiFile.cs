using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using JetBrains.Annotations;

namespace JetBrains.SignatureVerifier.Cf
{
  /// <summary>
  /// MS Windows Installer compound file
  /// </summary>
  public class MsiFile
  {
    private readonly CompoundFile _cf;

    //\u0005DigitalSignature
    private readonly byte[] _digitalSignatureEntryName = { 0x5, 0x0, 0x44, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x53, 0x00, 0x69, 0x00, 0x67, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00 };

    //\u0005MsiDigitalSignatureEx
    private readonly byte[] _msiDigitalSignatureExEntryName = { 0x5, 0x0, 0x4D, 0x00, 0x73, 0x00, 0x69, 0x00, 0x44, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x53, 0x00, 0x69, 0x00, 0x67, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00, 0x45, 0x00, 0x78, 0x00 };

    ///  <summary>
    /// Initializes a new instance of the <see cref="T:JetBrains.SignatureVerifier.Cf.MsiFile"></see>
    ///  </summary>
    ///  <param name="stream">An input stream</param>
    ///  <exception cref="PlatformNotSupportedException">Indicates the byte order ("endianness")
    ///  in which data is stored in this computer architecture is not Little Endian.</exception>
    ///  <exception cref="InvalidDataException">If the input stream contains a compound file with wrong structure</exception>
    public MsiFile([NotNull] Stream stream)
    {
      _cf = new CompoundFile(stream);
    }

    /// <summary>
    /// Retrieve the signature data from MSI
    /// </summary>
    public SignatureData GetSignatureData()
    {
      var data = _cf.GetStreamData(_digitalSignatureEntryName);

      if (data == null)
        return SignatureData.Empty;
      return new SignatureData(null, data);
    }

    /// <summary>
    /// Compute hash of MSI structure
    /// </summary>
    /// <param name="algName">Name of the hashing algorithm</param>
    /// <param name="skipMsiDigitalSignatureExEntry">Skip \u0005MsiDigitalSignatureEx entry data when hashing</param>
    /// <exception cref="ArgumentNullException">if algName is null</exception>
    public byte[] ComputeHash([NotNull] string algName, bool skipMsiDigitalSignatureExEntry)
    {
      if (algName == null) throw new ArgumentNullException(nameof(algName));

      var entries = _cf.GetStreamDirectoryEntries();
      entries.Sort(compareDirectoryEntries);

      using var hash = IncrementalHash.CreateHash(new HashAlgorithmName(algName.ToUpper()));

      foreach (var entry in entries)
      {
        if (entry.Name.SequenceEqual(_digitalSignatureEntryName))
          continue;

        if (skipMsiDigitalSignatureExEntry && entry.Name.SequenceEqual(_msiDigitalSignatureExEntryName))
          continue;

        var data = _cf.GetStreamData(entry);
        hash.AppendData(data);
      }

      var rootClsid = _cf.GetRootDirectoryClsid();

      if (rootClsid != null)
        hash.AppendData(rootClsid);

      return hash.GetHashAndReset();
    }

    private int compareDirectoryEntries(DirectoryEntry e1, DirectoryEntry e2)
    {
      var a = e1.Name;
      var b = e2.Name;

      var size = Math.Min(a.Length, b.Length);

      for (var i = 0; i < size; i++)
        if (a[i] != b[i])
          return (a[i] & 0xFF) - (b[i] & 0xFF);

      return a.Length - b.Length;
    }
  }
}