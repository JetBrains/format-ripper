# Usage

Following types of executable files are supported:

- for Portable executable (PE) files use `JetBrains.FormatRipper.Pe.PeFile`
- for Compound files or MS Windows Installer compound (MSI) files use `JetBrains.FormatRipper.Compound.CompoundFile`
- for ELF files use `JetBrains.FormatRipper.Elf.ElfFile`
- for Mach-O/Fat-Mach-O use `JetBrains.FormatRipper.MachO.MachOFile`

The client code should detect the file type and create an appropriate object to use.

# File type detection

In order to detect the file type `JetBrains.FormatRipper.FileExplorer.FileTypeExplorer` can be used.

```c#
using var stream = File.OpenRead(pathToFile);
var res = stream.DetectFileType();
System.Console.WriteLine($"{res.FileType}: {res.FileProperties}"); // Pe: SharedLibraryType, Managed, Signed
```

# Signature verification

## Signature verification parameters

In order to verify the signature of any supported executable the client code should create the
SignatureVerificationParams object and pass is to the call of `VerifySignatureAsync` method.

`SignatureVerificationParams` constructor apply following parameters:

- `signRootCertStore` - Stream of PKCS #7 store with CA certificates for which a chain will be build and validate
- `timestampRootCertStore` - Stream of PKCS #7 store with a timestamp CA certificates for which a chain will be build
  and validate
- `buildChain` - If true, build and verify a certificates chain (by default true)
- `withRevocationCheck` - If true, verify a revocation status for certificates in all chains (apply if buildChain is
  true, by default true)
- `ocspResponseTimeout` - Timeout for OCSP request (5 sec. by default, apply if withRevocationCheck is true)
- `signatureValidationTimeMode` - Mode of selection time which is used for certificates and CRLs validation (Timestamp
  by default)
- `signatureValidationTime` - Time which is used when `signatureValidationTimeMode` has `SignValidationTime` value

The timestamp CA certificates may be included in the separate PKCS#7 store file, and passed to
the `timestampRootCertStore` parameter.

Certificate revocation status checking is performed when
`withRevocationCheck` is true. The check is based on CRLs, but if it is not available, OCSP is used.

## Example


```c#
static Task Main(string[] args)
{
    var pathToMachO = args[0];
    var pathToPe = args[1];
    var logger = new SimpleConsoleLogger();
    return ResourceUtil.OpenDefaultRoots(async defaultRootsStream =>
        {
            var verificationParams = new SignatureVerificationParams(
                signRootCertStore: defaultRootsStream,
                timestampRootCertStore: null,
                buildChain: true,
                withRevocationCheck: false);
            await VerifyMachO(logger, pathToMachO, verificationParams);
            await VerifyPe(logger, pathToPe, verificationParams);
        });
}

static async Task VerifyMachO(ILogger logger, string path, SignatureVerificationParams verificationParams)
{
    using var stream = File.OpenRead(path);
    var file = MachOFile.Parse(stream, MachOFile.Mode.SignatureData);
    foreach (var section in file.Sections)
    {
        var result = await VerifySignature(logger, section.SignatureData, verificationParams);
        DisplayResult(logger, result);
    }
}

static async Task VerifyPe(ILogger logger, string path, SignatureVerificationParams verificationParams)
{
    using var stream = File.OpenRead(path);
    var file = PeFile.Parse(stream, PeFile.Mode.SignatureData);
    VerifySignatureResult result = await VerifySignature(logger, file.SignatureData, verificationParams);
    DisplayResult(logger, result);
}

static async Task<VerifySignatureResult> VerifySignature(ILogger logger, SignatureData signatureData, SignatureVerificationParams verificationParams)
{
    var signedMessage = SignedMessage.CreateInstance(signatureData);
    var signedMessageVerifier = new SignedMessageVerifier(logger);
    return await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
}

static void DisplayResult(ILogger logger, VerifySignatureResult result)
{
    if (result.Status == VerifySignatureStatus.Valid)
        logger.Info("Signature is VALID!");
    else
        logger.Error($"Signature is INVALID! {result.Message}");
}
```

# Hash computing

Following hashing algorithms are supported:

- MD5
- SHA1
- SHA256
- SHA384
- SHA512

In order to compute hash of the executable call the `HashUtil.ComputeHash()` method.

## Example

```c#
using var stream = File.OpenRead(pathToFile);
var file = PeFile.Parse(stream, PeFile.Mode.ComputeHashInfo);
var hash = HashUtil.ComputeHash(stream, file.ComputeHashInfo, HashAlgorithmName.SHA512);
```

# Additional

## Example of logger

```c#
class SimpleConsoleLogger : ILogger
{
   public void Info(string str) => System.Console.WriteLine($"INFO: {str}");
   public void Warning(string str) => System.Console.Error.WriteLine($"WARNING: {str}");
   public void Error(string str) => System.Console.Error.WriteLine($"ERROR: {str}");
   public void Trace(string str) => System.Console.Error.WriteLine($"TRACE: {str}");
}
```

## Default CA certificates

The library contains the `JetBrains.SignatureVerifier.ResourceUtil.OpenDefaultRoots()`
method which returns the stream of the PKCS#7 store with following root certificates:

| Issuer | Serial number | Not valid before | Not valid after | Thumbprint |
|:-|:-|:-:|:-:|:-|
| CN=Apple Root CA, OU=Apple Certification Authority, O=Apple Inc., C=US | 02 | 26.04.2006 1:40 | 10.02.2035 0:40 | 611E5B662C593A08FF58D14AE22452D198DF6C60 |
| CN=Certum Trusted Network CA, OU=Certum Certification Authority, O=Unizeto Technologies S.A., C=PL | 0444C0 | 22.10.2008 16:07 | 31.12.2029 15:07 | 07E032E020B72C3F192F0628A2593A19A70F069E |
| CN=Go Daddy Root Certificate Authority - G2, O="GoDaddy.com, Inc.", L=Scottsdale, S=Arizona, C=US | 00 | 01.09.2009 4:00 | 01.01.2038 2:59 | 47BEABC922EAE80E78783462A79F45C254FDE68B |
| CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US | 28CC3A25BFBA44AC449A9B586B4339AA | 24.06.2010 1:57 | 24.06.2035 1:04 | 3B1EFD3A66EA28B16697394703A72CA340A05BD5 |
| CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US | 3F8BC8B5FC9FB29643B569D66C42E144 | 23.03.2011 1:05 | 23.03.2036 1:13 | 8F43288AD272F3103B6FB1428485EA3014C0BCFE |
| CN=Microsoft Root Certificate Authority, DC=microsoft, DC=com | 79AD16A14AA0A5AD4C7358F407132E65 | 10.05.2001 3:19 | 10.05.2021 2:28 | CDD4EEAE6000AC7F40C3802C171E30148030C072 |
| CN=USERTrust RSA Certification Authority, O=The USERTRUST Network, L=Jersey City, S=New Jersey, C=US | 01FD6D30FCA3CA51A81BBC640E35032D | 01.02.2010 3:00 | 19.01.2038 2:59 | 2B8F1B57330DBBA2D07A6C51F70EE90DDAB9AD8E |
