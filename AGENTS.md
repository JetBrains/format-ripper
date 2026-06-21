---
project: Format ripper
languages: [C#, Kotlin]
build-system: Maven, dotnet
---

## Project structure

```
cert/               <- Test data for Kotlin and .NET parts
  DefaultRoots.p7b  <- Approved allowed root certificates for code signing using code-sign service
data/               <- Test files for Kotlin and .NET parts
  .test-data-root   <- Marker file, must be present in every test data directory
  dmg/              <- DMG test files
  elf/              <- ELF test files
  mach-o/           <- MachO test files
  misc/             <- Malformed test files
  msi/              <- MSI test files
  pe/               <- PE test files
  powershell/       <- PowerShell script test files
  sh/               <- Shebang script test files
jvm/                <- Kotlin sources and tests
net/                <- .NET sources and tests
  shared/           <- Sources shared by the .NET test projects
```

## Test data

The .NET tests read the test files from the disk, the `data/` directory isn't embedded into the test assemblies.
See `net/shared/TestDataUtil.cs`.

The primary test data directory is taken from the `JB_TEST_DATA` environment variable when it's defined, an absolute
path is required there. Otherwise the `data` subdirectory is looked up in the test assembly directory and in all its
parents.

The optional additional test data directory is always probed at `../../data` relative to the primary one, i.e. next to
the repository root, and is used as the second directory when it exists. It holds the images which are too big to be
stored in the repository, the tests using them are ignored when they are missing.

Every test data directory must contain the `.test-data-root` marker file, otherwise it's an error.

## Building and testing

### .NET

.NET 8.0 needs to be tested on all platforms. On Windows, make sure to run the tests for .NET Framework 3.5.