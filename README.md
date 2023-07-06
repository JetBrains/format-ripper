# JetBrains format-ripper [![official JetBrains project](https://jb.gg/badges/official.svg)](https://confluence.jetbrains.com/display/ALL/JetBrains+on+GitHub)

[![Build and run tests](https://github.com/JetBrains/format-ripper/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/JetBrains/format-ripper/actions/workflows/build-and-test.yml)

[![NuGet Badge](https://buildstats.info/nuget/JetBrains.FormatRipper)](https://www.nuget.org/packages/JetBrains.FormatRipper)
[![NuGet Badge](https://buildstats.info/nuget/JetBrains.SignatureVerifier)](https://www.nuget.org/packages/JetBrains.SignatureVerifier)
[![Maven Central](https://img.shields.io/maven-central/v/com.jetbrains.format-ripper/format-ripper)](https://mvnrepository.com/artifact/com.jetbrains.format-ripper)

JetBrains format-ripper library is applicable for:

- detect the type of software binaries
- determine the origin of software binaries via verification the cryptographic signatures
- determine the integrity of software binaries via computation and comparing the binaries hashes

Following types of software binaries files are supported:

- Portable executable (PE)
- MS Windows Installer (MSI)
- MachO
- Fat-MachO (Universal binaries)
- ELF

See further descriptions:

- .NET
https://github.com/JetBrains/format-ripper/tree/master/net#readme

- Java
https://github.com/JetBrains/format-ripper/tree/master/jvm#readme

