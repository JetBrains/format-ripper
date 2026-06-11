using System;
using System.IO;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class ReadOnlyAggregatedStreamTest
  {
    [Test]
    public void Test()
    {
      static byte[] CreateBuffer(int count)
      {
        var data = new byte[count];
        for (var n = 0; n < data.Length; n++)
          data[n] = 0xFF;
        return data;
      }

      static MemoryStream MakeStream(byte start, int count)
      {
        var data = new byte[count];
        for (var i = 0; i < count; i++)
          data[i] = (byte)(start + i);
        return new MemoryStream(data, false);
      }

      using var s = new ReadOnlyAggregatedStream(
        new MemoryStream(),
        MakeStream(0, 4),
        new MemoryStream(),
        new MemoryStream(),
        new MemoryStream(),
        MakeStream(4, 3),
        MakeStream(7, 5),
        new MemoryStream());
      Assert.IsTrue(s.CanRead);
      Assert.IsTrue(s.CanSeek);
      Assert.IsFalse(s.CanWrite);
      Assert.AreEqual(0, s.Position);
      Assert.AreEqual(12, s.Length);

      var buf = CreateBuffer(3);
      Assert.AreEqual(3, s.Read(buf, 0, 3));
      Assert.AreEqual(new byte[] { 0, 1, 2 }, buf);
      Assert.AreEqual(3, s.Position);

      buf = CreateBuffer(4);
      Assert.AreEqual(3, s.Read(buf, 1, 3));
      Assert.AreEqual(new byte[] { 0xFF, 3, 4, 5 }, buf);
      Assert.AreEqual(6, s.Position);

      buf = CreateBuffer(4);
      Assert.AreEqual(4, s.Read(buf, 0, 4));
      Assert.AreEqual(new byte[] { 6, 7, 8, 9 }, buf);
      Assert.AreEqual(10, s.Position);

      buf = CreateBuffer(5);
      Assert.AreEqual(2, s.Read(buf, 0, 5));
      Assert.AreEqual(new byte[] { 10, 11, 0xFF, 0xFF, 0xFF }, buf);
      Assert.AreEqual(12, s.Position);

      Assert.AreEqual(0, s.Read(buf, 0, 5));

      s.Seek(5, SeekOrigin.Begin);
      Assert.AreEqual(5, s.Position);
      buf = CreateBuffer(3);
      Assert.AreEqual(3, s.Read(buf, 0, 3));
      Assert.AreEqual(new byte[] { 5, 6, 7 }, buf);
      Assert.AreEqual(8, s.Position);

      s.Seek(-3, SeekOrigin.Current);
      Assert.AreEqual(5, s.Position);
      buf = CreateBuffer(1);
      Assert.AreEqual(1, s.Read(buf, 0, 1));
      Assert.AreEqual(new byte[] { 5 }, buf);
      Assert.AreEqual(6, s.Position);

      s.Seek(-2, SeekOrigin.End);
      Assert.AreEqual(10, s.Position);
      buf = CreateBuffer(3);
      Assert.AreEqual(2, s.Read(buf, 0, 3));
      Assert.AreEqual(new byte[] { 10, 11, 0xFF }, buf);
      Assert.AreEqual(12, s.Position);

      s.Seek(0, SeekOrigin.Begin);
      Assert.AreEqual(0, s.Position);
      buf = CreateBuffer(16);
      Assert.AreEqual(12, s.Read(buf, 2, 13));
      Assert.AreEqual(new byte[] { 0xFF, 0xFF, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0xFF, 0xFF }, buf);
      Assert.AreEqual(12, s.Position);

      Assert.Throws<ArgumentOutOfRangeException>(() => s.Seek(-1, SeekOrigin.Begin));
      Assert.Throws<ArgumentOutOfRangeException>(() => s.Seek(0, (SeekOrigin)99));

      Assert.Throws<NotSupportedException>(() => s.Write(new byte[1], 0, 1));
      Assert.Throws<NotSupportedException>(() => s.SetLength(5));
      Assert.Throws<NotSupportedException>(s.Flush);
      Assert.Throws<ArgumentOutOfRangeException>(() => s.Position = -1);
      Assert.Throws<ArgumentOutOfRangeException>(() => s.Position = s.Length + 1);
    }
  }
}
