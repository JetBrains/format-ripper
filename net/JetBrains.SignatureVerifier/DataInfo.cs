namespace JetBrains.SignatureVerifier
{
    readonly struct DataInfo
    {
        public DataInfo(int offset, int size)
        {
            Offset = offset;
            Size = size;
        }

        public bool IsEmpty => Offset == 0 && Size == 0;
        public int Offset { get; }
        public int Size { get; }
    }
}