using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using JetBrains.FormatRipper;

namespace SignatureExtractor;

class Program
{
  static async Task<int> Main(string[] args)
  {
    var extractInputOption = new Option<string>(new[] { "--input", "-i" }, "Path to the signed application whose signature is to be exported.") { IsRequired = true };
    var extractOutputOption = new Option<string>(new[] { "--output", "-o" }, "Path to save the signature.") { IsRequired = true };

    var extractCommand = new Command("extract", "Extract signature from the input file and save it to the output json file.")
    {
      extractInputOption, extractOutputOption
    };

    extractCommand.SetHandler(async (string inputFile, string output) => { await ExtractSignature(inputFile, output); }, extractInputOption, extractOutputOption);

    var applyInputOption = new Option<string>(new string[] { "--input", "-i" }, "Path to the application to which the signature should be applied.") { IsRequired = true };
    var applySignatureOption = new Option<string>(new string[] { "--signature", "-s" }, "Signature") { IsRequired = true };
    var applyOutputOption = new Option<string>(new string[] { "--output", "-o" }, "Path to save the resulting application.") { IsRequired = true };
    var applyDontVerifyResultsOption = new Option<bool>(new string[] { "--skip-verification" }, "Do not check the validity of the signature of the resulting file. If this flag is set, only the technical feasibility of signature transposition will be checked.") { IsRequired = false, Arity = ArgumentArity.ZeroOrOne };
    applyDontVerifyResultsOption.SetDefaultValue(false);

    var applyCommand = new Command("apply", "Apply previously extracted signature to the input file and save the result to the output file. If the input file is already signed, the signature will be replaced with the new one.")
    {
      applyInputOption, applySignatureOption, applyOutputOption, applyDontVerifyResultsOption
    };

    applyCommand.SetHandler(async (string inputFile, string signature, string output, bool skipVerification) => { await ApplySignature(inputFile, signature, output, skipVerification); }, applyInputOption, applySignatureOption, applyOutputOption, applyDontVerifyResultsOption);

    var rootCommand = new RootCommand("Utility to extract and apply signature from/to Mach-O, Dmg and PE file formats.")
    {
      extractCommand,
      applyCommand
    };

    var builder = new CommandLineBuilder(rootCommand)
      .UseDefaults()
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
      SignatureApplicationException => 3,
      _ => 255
    };

    invocationContext.ExitCode = errorCode;
  }

  public static async Task ExtractSignature(string inputFile, string output)
  {
    using Stream inputFileStream = File.OpenRead(inputFile);
    using Stream outputStream = File.OpenWrite(output);

    await SignatureOperations.ExtractSignature(inputFileStream, outputStream);
  }

  public static async Task ApplySignature(string inputFile, string signatureFile, string output, bool verifyResults)
  {
    using Stream inputFileStream = File.OpenRead(inputFile);
    using Stream signatureFileStream = File.OpenRead(signatureFile);
    using Stream outputStream = File.Open(output, FileMode.Create, FileAccess.ReadWrite);

    await SignatureOperations.ApplySignature(inputFileStream, signatureFileStream, outputStream, verifyResults);
  }
}