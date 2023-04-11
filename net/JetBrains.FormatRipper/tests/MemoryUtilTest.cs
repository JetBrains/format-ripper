using System;
using JetBrains.FormatRipper.Impl;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class MemoryUtilTest
  {
    [TestCase((ushort)0x1234, (ushort)0x3412)]
    [TestCase((ushort)0xbcef, (ushort)0xefbc)]
    [Test]
    public void SwapU2Test(ushort value, ushort expectedValue) => Assert.AreEqual(expectedValue, MemoryUtil.SwapU2(value));

    [TestCase(0x12345678u, 0x78563412u)]
    [TestCase(0x9abcdef0u, 0xf0debc9au)]
    [Test]
    public void SwapU4Test(uint value, uint expectedValue) => Assert.AreEqual(expectedValue, MemoryUtil.SwapU4(value));

    [TestCase(0x1234567887654321ul, 0x2143658778563412ul)]
    [TestCase(0x9abcdef087654321ul, 0x21436587f0debc9aul)]
    [Test]
    public void SwapU8Test(ulong value, ulong expectedValue) => Assert.AreEqual(expectedValue, MemoryUtil.SwapU8(value));

    [TestCase("00112233-4455-6677-8899-aabbccddeeff", "33221100-5544-7766-8899-aabbccddeeff")]
    [TestCase("0526d872-e70d-421f-818a-20c0e7c2bb6c", "72d82605-0de7-1f42-818a-20c0e7c2bb6c")]
    [Test]
    public void SwapGuidTest(string value, string expectedValue) => Assert.AreEqual(expectedValue, MemoryUtil.SwapGuid(new Guid(value)).ToString("D"));
  }
}