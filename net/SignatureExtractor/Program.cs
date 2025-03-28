using System.CommandLine;
using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.FileExplorer;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.Pe;
using Newtonsoft.Json;

namespace SignatureExtractor;

record SignatureContainer(FileType FileType, MachOSignatureTransferData? MachOSignatureTransferData, PeSignatureTransferData? PeSignatureTransferData, DmgSignatureTransferData? DmgSignatureTransferData);

class Program
{
  static async Task<int> Main(string[] args)
  {
    var extractSourceOption = new Option<string>(new string[] { "--source", "-s" }, "Path to the application whose signature is to be exported") { IsRequired = true };

    var extractOutputOption = new Option<string>(new string[] { "--output", "-o" }, "Path to save the signature. By default, the signature will be printed to stdout.") { IsRequired = false };

    var extractCommand = new Command("extract", "Extract signature from the input file")
    {
      extractSourceOption, extractOutputOption
    };

    extractCommand.SetHandler((string inputFile, string output) => { ExtractSignature(inputFile, output); }, extractSourceOption, extractOutputOption);

    var applySourceOption = new Option<string>(new string[] { "--source" }, "Path to the application to which the signature should be applied") { IsRequired = true };
    var applySignatureOption = new Option<string>(new string[] { "--signature" }, "Signature") { IsRequired = true };
    var applyOutputOption = new Option<string>(new string[] { "--output", "-o" }, "Path to save the resulting application. By default, the resulting application will be printed to stdout.") { IsRequired = false };

    var applyCommand = new Command("apply", "Apply signature to the input file")
    {
      applySourceOption, applySignatureOption, applyOutputOption
    };

    applyCommand.SetHandler((string inputFile, string signature, string output) => { ApplySignature(inputFile, signature, output); }, applySourceOption, applySignatureOption, applyOutputOption);

    var rootCommand = new RootCommand("Utility to extract and apply signature from/to various file formats")
    {
      extractCommand,
      applyCommand
    };

    return await rootCommand.InvokeAsync(args);
  }

  static void ExtractSignature(string inputFile, string output)
  {
    using var fileStream = File.OpenRead(inputFile);
    var fileType = FileTypeExplorer.Detect(fileStream);
    fileStream.Seek(0, SeekOrigin.Begin);

    var signatureContainer = fileType.FileType switch
    {
      FileType.MachO => ExtractMachOSignatures(fileStream),
      FileType.Pe => ExtractPeSignatures(fileStream),
      FileType.Dmg => ExtractDmgSignatures(fileStream),
      _ => throw new Exception("Unknown file type")
    };

    fileStream.Close();

    var settings = new JsonSerializerSettings()
    {
      Converters = { new Newtonsoft.Json.Converters.StringEnumConverter() },
      Formatting = Formatting.Indented,
      NullValueHandling = NullValueHandling.Ignore,
    };

    var serialized = JsonConvert.SerializeObject(signatureContainer, settings);

    if (!string.IsNullOrEmpty(output))
      File.WriteAllText(output, serialized);
    else
      Console.Write(serialized);
  }

  static SignatureContainer ExtractMachOSignatures(Stream stream)
  {
    MachOFile parsedFile = MachOFile.Parse(stream, MachOFile.Mode.SignatureData);

    if (parsedFile.Signature == null)
      throw new Exception("No signature found");

    return new SignatureContainer(FileType.MachO, parsedFile.Signature, null, null);
  }

  static SignatureContainer ExtractPeSignatures(Stream stream)
  {
    PeFile parsedFile = PeFile.Parse(stream, PeFile.Mode.SignatureData);

    if (parsedFile.SignatureTransferData == null)
      throw new Exception("No signature found");

    return new SignatureContainer(FileType.Pe, null, parsedFile.SignatureTransferData, null);
  }

  static SignatureContainer ExtractDmgSignatures(Stream stream)
  {
    DmgFile parsedFile = DmgFile.Parse(stream, DmgFile.Mode.SignatureData);

    if (parsedFile.SignatureTransferData == null)
      throw new Exception("No signature found");

    return new SignatureContainer(FileType.Dmg, null, null, parsedFile.SignatureTransferData);
  }

  static void ApplySignature(string inputFile, string signatureFile, string output)
  {
    var signature = File.ReadAllText(signatureFile);

    var settings = new JsonSerializerSettings()
    {
      Converters = { new Newtonsoft.Json.Converters.StringEnumConverter() },
      Formatting = Formatting.Indented,
      NullValueHandling = NullValueHandling.Ignore,
    };

    var signatureContainer = JsonConvert.DeserializeObject<SignatureContainer>(signature, settings);

    if (signatureContainer == null)
      throw new Exception("Failed to deserialize signature");

    using var fileStream = File.OpenRead(inputFile);
    var fileType = FileTypeExplorer.Detect(fileStream);
    fileStream.Seek(0, SeekOrigin.Begin);

    if (fileType.FileType != signatureContainer.FileType)
      throw new Exception("File type mismatch");

    Stream outputStream = !string.IsNullOrEmpty(output) ? File.OpenWrite(output) : Console.OpenStandardOutput();

    switch (fileType.FileType)
    {
      case FileType.MachO:
        ApplyMachOSignature(fileStream, signatureContainer.MachOSignatureTransferData, outputStream);
        break;
      case FileType.Pe:
        ApplyPeSignature(fileStream, signatureContainer.PeSignatureTransferData, outputStream);
        break;
      case FileType.Dmg:
        ApplyDmgSignature(fileStream, signatureContainer.DmgSignatureTransferData, outputStream);
        break;
      default:
        throw new Exception("Unknown file type");
    }

    fileStream.Close();
  }

  static void ApplyMachOSignature(Stream inputStream, MachOSignatureTransferData? signature, Stream outputStream)
  {
    if (signature == null) throw new Exception("No signature found");
    MachOSignatureInjector.InjectSignature(inputStream, outputStream, signature);
  }

  static void ApplyPeSignature(Stream inputStream, PeSignatureTransferData? signature, Stream outputStream)
  {
    if (signature == null) throw new Exception("No signature found");
    PeSignatureInjector.InjectSignature(inputStream, outputStream, signature);
  }

  static void ApplyDmgSignature(Stream inputStream, DmgSignatureTransferData? signature, Stream outputStream)
  {
    if (signature == null) throw new Exception("No signature found");
    DmgSignatureInjector.InjectSignature(inputStream, outputStream, signature);
  }
}