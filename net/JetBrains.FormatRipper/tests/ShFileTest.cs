using JetBrains.FormatRipper.Sh;
using JetBrains.Tests;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class ShFileTest
  {
    [TestCase("1.sh")]
    [TestCase("2.sh")]
    [Test]
    public void Test(string resourceName)
    {
      TestDataUtil.OpenRead(ResourceCategory.Sh, resourceName, stream =>
        {
          Assert.IsTrue(ShFile.Is(stream));
        });
    }
  }
}