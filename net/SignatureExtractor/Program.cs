using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using JetBrains.FormatRipper;
using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.FileExplorer;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.Pe;

namespace SignatureExtractor;

record SignatureContainer(FileType FileType, MachOSignatureTransferData? MachOSignatureTransferData, PeSignatureTransferData? PeSignatureTransferData, DmgSignatureTransferData? DmgSignatureTransferData);

class Program
{
  static async Task<int> Main(string[] args)
  {
    var extractSourceOption = new Option<string>(new[] { "--source", "-s" }, "Path to the application whose signature is to be exported") { IsRequired = true };
    var extractOutputOption = new Option<string>(new[] { "--output", "-o" }, "Path to save the signature") { IsRequired = true };

    var extractCommand = new Command("extract", "Extract signature from the input file")
    {
      extractSourceOption, extractOutputOption
    };

    extractCommand.SetHandler((string inputFile, string output) => { SignatureOperations.ExtractSignature(inputFile, output); }, extractSourceOption, extractOutputOption);

    var applySourceOption = new Option<string>(new string[] { "--source" }, "Path to the application to which the signature should be applied") { IsRequired = true };
    var applySignatureOption = new Option<string>(new string[] { "--signature" }, "Signature") { IsRequired = true };
    var applyOutputOption = new Option<string>(new string[] { "--output", "-o" }, "Path to save the resulting application") { IsRequired = true };
    var applyDontVerifyResultsOption = new Option<bool>(new string[] { "--skip-verification" }, "Do not veryfy the resulting file") { IsRequired = false, Arity = ArgumentArity.ZeroOrOne };
    applyDontVerifyResultsOption.SetDefaultValue(false);

    var applyCommand = new Command("apply", "Apply signature to the input file")
    {
      applySourceOption, applySignatureOption, applyOutputOption, applyDontVerifyResultsOption
    };

    applyCommand.SetHandler(async (string inputFile, string signature, string output, bool skipVerification) => { await SignatureOperations.ApplySignature(inputFile, signature, output, skipVerification); }, applySourceOption, applySignatureOption, applyOutputOption, applyDontVerifyResultsOption);

    var rootCommand = new RootCommand("Utility to extract and apply signature from/to various file formats")
    {
      extractCommand,
      applyCommand
    };

    var builder = new CommandLineBuilder(rootCommand)
      .UseExceptionHandler(OnException)
      .Build();

    int errorCode = await builder.InvokeAsync(args);

    return errorCode;
  }

  static void OnException(Exception exception, InvocationContext invocationContext)
  {
    Console.Error.WriteLine(exception.Message);
    int errorCode = exception switch
    {
      SignatureExtractionException => 1,
      SignatureInjectionException => 2,
      _ => 255
    };

    invocationContext.ExitCode = errorCode;
  }
}