using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.FileExplorer;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using Newtonsoft.Json;

namespace SignatureExtractor;

public static class SignatureOperations
{
  public static async Task ExtractSignature(Stream inputFile, Stream output)
  {
    if (!inputFile.CanSeek)
      throw new SignatureExtractionException("Input file must be seekable");

    var fileType = FileTypeExplorer.Detect(inputFile);
    inputFile.Seek(0, SeekOrigin.Begin);

    var signatureContainer = fileType.FileType switch
    {
      FileType.MachO => ExtractMachOSignatures(inputFile),
      FileType.Pe => ExtractPeSignatures(inputFile),
      FileType.Dmg => ExtractDmgSignatures(inputFile),
      _ => throw new SignatureExtractionException($"Unsupported file type: {fileType.FileType}.")
    };

    var settings = new JsonSerializerSettings()
    {
      Converters = { new Newtonsoft.Json.Converters.StringEnumConverter() },
      Formatting = Formatting.Indented,
      NullValueHandling = NullValueHandling.Ignore,
    };

    using (StreamWriter writer = new StreamWriter(output, leaveOpen: true))
    using (JsonTextWriter jsonWriter = new JsonTextWriter(writer))
    {
      JsonSerializer ser = JsonSerializer.Create(settings);
      ser.Serialize(jsonWriter, signatureContainer);
      await jsonWriter.FlushAsync();
    }
  }

  static SignatureContainer ExtractMachOSignatures(Stream stream)
  {
    MachOFile parsedFile = MachOFile.Parse(stream, MachOFile.Mode.SignatureData);

    if (parsedFile.Signature == null || parsedFile.Signature.SectionSignatures.Length == 0)
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

  public static async Task ApplySignature(Stream inputFile, Stream signatureFile, Stream outputStream, bool verifyResults)
  {
    if (!inputFile.CanSeek)
      throw new SignatureApplicationException("Input file must be seekable");

    if (verifyResults && !outputStream.CanSeek)
      throw new SignatureApplicationException("Output file must be seekable if results verification is enabled");

    SignatureContainer? signatureContainer = null;
    using (StreamReader reader = new StreamReader(signatureFile, leaveOpen: true))
    using (JsonTextReader jsonReader = new JsonTextReader(reader))
    {
      JsonSerializer ser = new JsonSerializer();
      signatureContainer = ser.Deserialize<SignatureContainer>(jsonReader);
    }

    if (signatureContainer == null)
      throw new SignatureApplicationException("Failed to deserialize signature");

    var fileType = FileTypeExplorer.Detect(inputFile);
    inputFile.Seek(0, SeekOrigin.Begin);

    if (fileType.FileType != signatureContainer.FileType)
      throw new SignatureApplicationException($"File type mismatch. Signature was extracted from {signatureContainer.FileType} file, but applied to {fileType.FileType} file.");

    var verifyResult = fileType.FileType switch
    {
      FileType.MachO => await ApplyMachOSignature(inputFile, signatureContainer.MachOSignatureTransferData, outputStream, verifyResults),
      FileType.Pe => await ApplyPeSignature(inputFile, signatureContainer.PeSignatureTransferData, outputStream, verifyResults),
      FileType.Dmg => await ApplyDmgSignature(inputFile, signatureContainer.DmgSignatureTransferData, outputStream, verifyResults),
      _ => throw new SignatureApplicationException($"Unsupported file type: {fileType.FileType}.")
    };

    if (verifyResult != null && !verifyResult.IsValid)
      throw new SignatureApplicationException(verifyResult.Message);
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

      PeFile acceptorFile = PeFile.Parse(outputStream, PeFile.Mode.SignatureData | PeFile.Mode.ComputeHashInfo);
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