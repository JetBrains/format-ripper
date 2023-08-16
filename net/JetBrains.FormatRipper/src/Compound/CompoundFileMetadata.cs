using System;
using System.Collections.Generic;
using System.Text;
using JetBrains.FormatRipper.Compound.Impl;

namespace JetBrains.FormatRipper.Compound;

public class CompoundFileMetadata
{

  public static string[] specialValues =
  {
    new(Encoding.Unicode.GetChars(new byte[] { 64, 72, 63, 59, 242, 67, 56, 68, 177, 69 })),
    new(Encoding.Unicode.GetChars(new byte[] { 64, 72, 63, 63, 119, 69, 108, 68, 106, 62, 178, 68, 47, 72 })),
    "MsiDigitalSignatureEx"
  };
}