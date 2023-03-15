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
    public void SwapU2Test(ushort expectedValue, ushort value) => Assert.AreEqual(expectedValue, MemoryUtil.SwapU2(value));

    [TestCase(0x12345678u, 0x78563412u)]
    [TestCase(0x9abcdef0u, 0xf0debc9au)]
    [Test]
    public void SwapU4Test(uint expectedValue, uint value) => Assert.AreEqual(expectedValue, MemoryUtil.SwapU4(value));

    [TestCase(0x1234567887654321ul, 0x2143658778563412ul)]
    [TestCase(0x9abcdef087654321ul, 0x21436587f0debc9aul)]
    [Test]
    public void SwapU8Test(ulong expectedValue, ulong value) => Assert.AreEqual(expectedValue, MemoryUtil.SwapU8(value));

    [TestCase("0526d872-e70d-421f-818a-20c0e7c2bb6c", "e7c2bb6c-20c0-818a-421f-e70d0526d872")]
    [TestCase("ddeeff00-bbcc-99aa-7788-556611223344", "11223344-5566-7788-99aa-bbccddeeff00")]
    [Test]
    public void SwapU8Test(string expectedValue, string value) => Assert.AreEqual(new Guid(expectedValue), MemoryUtil.SwapGuid(new Guid(value)));
  }
}