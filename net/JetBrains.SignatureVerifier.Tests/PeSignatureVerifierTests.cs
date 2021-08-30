using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.IO;
using System.Threading.Tasks;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public class PeSignatureVerifierTests
    {
        private const string pe_01_signed = "ServiceModelRegUI.dll";
        private const string pe_01_not_signed = "ServiceModelRegUI_no_sign.dll";
        private const string pe_01_trimmed_sign = "ServiceModelRegUI_trimmed_sign.dll";
        private const string pe_01_empty_sign = "ServiceModelRegUI_empty_sign.dll";
        private const string pe_01_broken_hash = "ServiceModelRegUI_broken_hash.dll";
        private const string pe_01_sha1 = "D64EC6AEC642441554E7CBA0E0513E35683C87AE";
        private const string pe_01_broken_sign = "ServiceModelRegUI_broken_sign.dll";
        private const string pe_01_broken_counter_sign = "ServiceModelRegUI_broken_counter_sign.dll";
        private const string pe_01_broken_nested_sign = "ServiceModelRegUI_broken_nested_sign.dll";
        private const string pe_01_broken_nested_sign_timestamp = "ServiceModelRegUI_broken_nested_sign_timestamp.dll";
        private const string pe_01_sha256 = "834394AC48C8AB8F6D21E64A2461BA196D28140558D36430C057E49ADF41967A";
        private const string ms_codesign_roots = "ms_codesign_roots.p7b";
        private const string ms_timestamp_root = "ms_timestamp_root.p7b";

        private const string pe_02_empty_sign = "uninst.exe";
        private const string pe_02_sha1 = "58AA2C6CF6A446426F3596F1BC4AB4E1FAAC297A";

        private const string pe_03_signed = "shell32.dll";
        private const string pe_03_sha256 = "BB79CC7089BF061ED707FFB3FFA4ADE1DDAED0396878CC92D54A0E20A3C81619";

        private const string pe_04_signed = "IntelAudioService.exe";
        private const string pe_04_sha256 = "160F2FE667A9252AB5B2E01749CD40B024E749B10B49AD276345875BA073A57E";

        private const string pe_05_signed = "libcrypto-1_1-x64.dll";
        private const string pe_06_signed = "libssl-1_1-x64.dll";
        private const string pe_07_signed = "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe";
        private const string jb_codesign_roots = "jb_codesign_roots.p7b";
        private const string jb_timestamp_roots = "jb_timestamp_roots.p7b";

        private const string pe_08_signed = "dotnet.exe";
        private const string pe_09_broken_timestamp = "dotnet_broken_timestamp.exe";

        [TestCase(pe_01_signed, VerifySignatureResult.OK)]
        [TestCase(pe_01_not_signed, VerifySignatureResult.NotSigned)]
        [TestCase(pe_01_trimmed_sign, VerifySignatureResult.NotSigned)]
        [TestCase(pe_01_empty_sign, VerifySignatureResult.NotSigned)]
        [TestCase(pe_01_broken_hash, VerifySignatureResult.InvalidSignature)]
        [TestCase(pe_01_broken_sign, VerifySignatureResult.InvalidSignature)]
        [TestCase(pe_01_broken_counter_sign, VerifySignatureResult.InvalidSignature)]
        [TestCase(pe_01_broken_nested_sign, VerifySignatureResult.InvalidSignature)]
        [TestCase(pe_01_broken_nested_sign_timestamp, VerifySignatureResult.InvalidTimestamp)]
        [TestCase(pe_02_empty_sign, VerifySignatureResult.NotSigned)]
        [TestCase(pe_03_signed, VerifySignatureResult.OK)]
        [TestCase(pe_04_signed, VerifySignatureResult.OK)]
        [TestCase(pe_05_signed, VerifySignatureResult.InvalidSignature)]
        [TestCase(pe_06_signed, VerifySignatureResult.InvalidSignature)]
        [TestCase(pe_07_signed, VerifySignatureResult.OK)]
        [TestCase(pe_09_broken_timestamp, VerifySignatureResult.InvalidTimestamp)]
        public async Task VerifySignTest(string peResourceName, VerifySignatureResult expectedResult)
        {
            var result = await Utils.StreamFromResource(peResourceName,
                async peFileStream => await new PeFile(peFileStream).VerifySignatureAsync(null, null, false));

            Assert.AreEqual(expectedResult, result);
        }

        [TestCase(pe_01_signed, VerifySignatureResult.OK, ms_codesign_roots, ms_timestamp_root, false)]
        [TestCase(pe_07_signed, VerifySignatureResult.OK, jb_codesign_roots, jb_timestamp_roots, true)]
        [TestCase(pe_08_signed, VerifySignatureResult.OK, ms_codesign_roots, ms_timestamp_root, true)]
        public async Task VerifySignWithChainTest(string peResourceName,
            VerifySignatureResult expectedResult,
            string codesignRootCertStoreResourceName,
            string timestampRootCertStoreResourceName,
            bool withRevocationCheck)
        {
            var result = await Utils.StreamFromResource(peResourceName,
                pe =>
                    Utils.StreamFromResource(codesignRootCertStoreResourceName,
                        codesignroots =>
                            Utils.StreamFromResource(timestampRootCertStoreResourceName, async timestamproots =>
                                await new PeFile(pe).VerifySignatureAsync(codesignroots, timestamproots,
                                    withRevocationCheck))));

            Assert.AreEqual(expectedResult, result);
        }

        [TestCase(pe_01_signed, "SHA1", pe_01_sha1)]
        [TestCase(pe_01_not_signed, "SHA1", pe_01_sha1)]
        [TestCase(pe_01_signed, "SHA256", pe_01_sha256)]
        [TestCase(pe_01_not_signed, "SHA256", pe_01_sha256)]
        [TestCase(pe_01_trimmed_sign, "SHA1", pe_01_sha1)]
        [TestCase(pe_01_empty_sign, "SHA1", pe_01_sha1)]
        [TestCase(pe_02_empty_sign, "SHA1", pe_02_sha1)]
        [TestCase(pe_03_signed, "SHA256", pe_03_sha256)]
        [TestCase(pe_04_signed, "SHA256", pe_04_sha256)]
        public void ComputeHashTest(string peResourceName, string alg, string expectedResult)
        {
            var result = Utils.StreamFromResource(peResourceName,
                peFileStream => new PeFile(peFileStream).ComputeHash(alg));

            Assert.AreEqual(expectedResult, Utils.ConvertToHexString(result));
        }
    }
}