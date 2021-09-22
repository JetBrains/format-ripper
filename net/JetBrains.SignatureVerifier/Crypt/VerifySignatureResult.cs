namespace JetBrains.SignatureVerifier
{
    public class VerifySignatureResult
    {
        private readonly VerifySignatureStatus _status;
        public VerifySignatureStatus Status => _status;
        public bool NotValid => _status != VerifySignatureStatus.Valid;
        public string Message { get; set; }
        public static VerifySignatureResult Valid = new VerifySignatureResult(VerifySignatureStatus.Valid);
        public static VerifySignatureResult NotSigned = new VerifySignatureResult(VerifySignatureStatus.NotSigned);

        public VerifySignatureResult(VerifySignatureStatus status)
        {
            _status = status;
        }

        public static VerifySignatureResult InvalidChain(string message) =>
            new VerifySignatureResult(VerifySignatureStatus.InvalidChain)
                { Message = message };
    }

    public enum VerifySignatureStatus
    {
        Valid,
        NotSigned,
        InvalidSignature,
        InvalidChain,
        InvalidTimestamp
    }
}