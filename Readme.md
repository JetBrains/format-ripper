---
JetBrains format-ripper usage
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

