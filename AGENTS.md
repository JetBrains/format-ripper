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
  dmg/              <- DMG test files
  elf/              <- ELF test files
  mach-o/           <- MachO test files
  msi/              <- MSI test files
  pe/               <- PE test files
  powershell/       <- PowerShell script test files
  sh/               <- Shebang script test files
jvm/                <- Kotlin sources and tests
net/                <- .NET sources and tests
```

## Building and testing

### .NET

.NET 8.0 needs to be tested on all platforms. On Windows, make sure to run the tests for .NET Framework 3.5.