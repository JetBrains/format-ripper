[![JetBrains incubator project](https://jb.gg/badges/incubator.svg)](https://confluence.jetbrains.com/display/ALL/JetBrains+on+GitHub)
[![Maven Central](https://img.shields.io/maven-central/v/com.jetbrains.format-ripper/format-ripper)](https://mvnrepository.com/artifact/com.jetbrains.format-ripper)
---
JetBrains format-ripper
---

JetBrains format-ripper library is applicable for:

- determine the origin of software binaries via verification the cryptographic signatures
- determine the integrity of software binaries via computation and comparing the binaries hashes

Following types of software binaries files are supported:

- Portable executable (PE)
- MachO
- Fat-MachO (Universal binaries)

Detection of the file type is not part of this library. The client code should detect the file type and create
appropriate object to use.

See further descriptions:

- .NET
https://github.com/JetBrains/format-ripper/tree/master/net/JetBrains.SignatureVerifier#readme

- Java
https://github.com/JetBrains/format-ripper/tree/master/jvm#readme

