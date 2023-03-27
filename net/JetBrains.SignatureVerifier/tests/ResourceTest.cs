using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  [TestFixture]
  public sealed class ResourceTest
  {
    [Test]
    public void Test() => SignatureVerifier.ResourceUtil.OpenDefaultRoots(_ => false);
  }
}