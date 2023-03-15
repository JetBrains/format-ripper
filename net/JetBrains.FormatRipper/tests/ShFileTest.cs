using JetBrains.FormatRipper.Sh;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class ShFileTest
  {
    [TestCase("1.sh")]
    [TestCase("2.sh")]
    [Test]
    public void Test(string filename)
    {
      ResourceUtil.OpenRead("Sh." + filename, stream =>
        {
          Assert.IsTrue(ShFile.Is(stream));
          return false;
        });
    }
  }
}