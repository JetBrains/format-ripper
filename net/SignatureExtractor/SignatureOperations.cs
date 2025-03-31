using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.FileExplorer;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using Newtonsoft.Json;

namespace SignatureExtractor;

public static class SignatureOperations
{
  public static void ExtractSignature(string inputFile, string output)
  {
    using var fileStream = File.OpenRead(inputFile);
    var fileType = FileTypeExplorer.Detect(fileStream);
    fileStream.Seek(0, SeekOrigin.Begin);

    var signatureContainer = fileType.FileType switch
    {
      FileType.MachO => ExtractMachOSignatures(fileStream),
      FileType.Pe => ExtractPeSignatures(fileStream),
      FileType.Dmg => ExtractDmgSignatures(fileStream),
      _ => throw new SignatureExtractionException($"Unsupported file type: {fileType.FileType}.")
    };

    fileStream.Close();

    var settings = new JsonSerializerSettings()
    {
      Converters = { new Newtonsoft.Json.Converters.StringEnumConverter() },
      Formatting = Formatting.Indented,
      NullValueHandling = NullValueHandling.Ignore,
    };

    var serialized = JsonConvert.SerializeObject(signatureContainer, settings);

    File.WriteAllText(output, serialized);
  }

  static SignatureContainer ExtractMachOSignatures(Stream stream)
  {
    MachOFile parsedFile = MachOFile.Parse(stream, MachOFile.Mode.SignatureData);

    if (parsedFile.Signature == null)
      throw new SignatureExtractionException("No signature found");

    return new SignatureContainer(FileType.MachO, parsedFile.Signature, null, null);
  }

  static SignatureContainer ExtractPeSignatures(Stream stream)
  {
    PeFile parsedFile = PeFile.Parse(stream, PeFile.Mode.SignatureData);

    if (parsedFile.SignatureTransferData == null)
      throw new SignatureExtractionException("No signature found");

    return new SignatureContainer(FileType.Pe, null, parsedFile.SignatureTransferData, null);
  }

  static SignatureContainer ExtractDmgSignatures(Stream stream)
  {
    DmgFile parsedFile = DmgFile.Parse(stream, DmgFile.Mode.SignatureData);

    if (parsedFile.SignatureTransferData == null)
      throw new SignatureExtractionException("No signature found");

    return new SignatureContainer(FileType.Dmg, null, null, parsedFile.SignatureTransferData);
  }

  public static async Task ApplySignature(string inputFile, string signatureFile, string output, bool verifyResults)
  {
    var signature = File.ReadAllText(signatureFile);

    var signatureContainer = JsonConvert.DeserializeObject<SignatureContainer>(signature);

    if (signatureContainer == null)
      throw new SignatureApplicationException("Failed to deserialize signature");

    using var fileStream = File.OpenRead(inputFile);
    var fileType = FileTypeExplorer.Detect(fileStream);
    fileStream.Seek(0, SeekOrigin.Begin);

    if (fileType.FileType != signatureContainer.FileType)
      throw new SignatureApplicationException($"File type mismatch. Signature was extracted from {signatureContainer.FileType} file, but applied to {fileType.FileType} file.");

    using Stream outputStream = File.Open(output, FileMode.Create, FileAccess.ReadWrite);

    var verifyResult = fileType.FileType switch
    {
      FileType.MachO => await ApplyMachOSignature(fileStream, signatureContainer.MachOSignatureTransferData, outputStream, verifyResults),
      FileType.Pe => await ApplyPeSignature(fileStream, signatureContainer.PeSignatureTransferData, outputStream, verifyResults),
      FileType.Dmg => await ApplyDmgSignature(fileStream, signatureContainer.DmgSignatureTransferData, outputStream, verifyResults),
      _ => throw new SignatureApplicationException($"Unsupported file type: {fileType.FileType}.")
    };

    outputStream.Close();
    fileStream.Close();

    if (verifyResult != null && !verifyResult.IsValid)
      throw new Exception(verifyResult.Message);
  }

  static async Task<VerifySignatureResult?> ApplyMachOSignature(Stream inputStream, MachOSignatureTransferData? signature, Stream outputStream, bool verifyResults)
  {
    if (signature == null) throw new Exception("No signature found");
    MachOSignatureInjector.InjectSignature(inputStream, outputStream, signature);

    VerifySignatureResult? result = null;

    if (verifyResults && outputStream.CanSeek)
    {
      outputStream.Seek(0, SeekOrigin.Begin);

      MachOFile acceptorFile = MachOFile.Parse(outputStream, MachOFile.Mode.SignatureData);
      var verificationParams = new SignatureVerificationParams(null, null, false, false, allowAdhocSignatures: true);
      MachOSignatureVerifier signatureVerifier = new MachOSignatureVerifier(logger: null);
      result = await signatureVerifier.VerifyAsync(acceptorFile, outputStream, verificationParams, FileIntegrityVerificationParams.Default);
    }

    return result;
  }

  static async Task<VerifySignatureResult?> ApplyPeSignature(Stream inputStream, PeSignatureTransferData? signature, Stream outputStream, bool verifyResults)
  {
    if (signature == null) throw new Exception("No signature found");
    PeSignatureInjector.InjectSignature(inputStream, outputStream, signature);
    VerifySignatureResult? result = null;

    if (verifyResults && outputStream.CanSeek)
    {
      outputStream.Seek(0, SeekOrigin.Begin);

      PeFile acceptorFile = PeFile.Parse(outputStream, PeFile.Mode.SignatureData);
      var verificationParams = new SignatureVerificationParams(null, null, false, false, allowAdhocSignatures: true);
      AuthenticodeSignatureVerifier signatureVerifier = new AuthenticodeSignatureVerifier(logger: null);
      result = await signatureVerifier.VerifyAsync(acceptorFile, outputStream, verificationParams, FileIntegrityVerificationParams.Default);
    }

    return result;
  }

  static async Task<VerifySignatureResult?> ApplyDmgSignature(Stream inputStream, DmgSignatureTransferData? signature, Stream outputStream, bool verifyResults)
  {
    if (signature == null) throw new Exception("No signature found");
    DmgSignatureInjector.InjectSignature(inputStream, outputStream, signature);
    VerifySignatureResult? result = null;

    if (verifyResults && outputStream.CanSeek)
    {
      outputStream.Seek(0, SeekOrigin.Begin);

      DmgFile acceptorFile = DmgFile.Parse(outputStream, DmgFile.Mode.SignatureData);
      var verificationParams = new SignatureVerificationParams(null, null, false, false, allowAdhocSignatures: true);
      DmgSignatureVerifier signatureVerifier = new DmgSignatureVerifier(logger: null);
      result = await signatureVerifier.VerifyAsync(acceptorFile, outputStream, verificationParams, FileIntegrityVerificationParams.Default);
    }

    return result;
  }
}