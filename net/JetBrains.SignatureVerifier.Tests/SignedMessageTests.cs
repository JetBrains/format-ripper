using System.IO;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
    //TODO acoder84 internal
    public class SignedMessageTests
    {
        public string dir = @"C:\Users\Anton.Vladimirov\Documents\signtest";
        
        [TestCase("ServiceModelRegUI.p7b", VerifySignatureResult.OK)]
        public void VerifySignTest(string resourceName, VerifySignatureResult expectedResult)
        {
            var path = Path.Combine(dir, resourceName);
            var data = File.ReadAllBytes(path);
            var result = new SignedMessage(data).VerifySignature(null);

            Assert.AreEqual(expectedResult, result);
        }
    }
}