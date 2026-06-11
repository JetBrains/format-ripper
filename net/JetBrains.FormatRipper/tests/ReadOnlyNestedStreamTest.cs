using System;
using System.IO;
using JetBrains.FormatRipper.Impl;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class ReadOnlyNestedStreamTest
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

      static MemoryStream MakeStream(int size)
      {
        var data = new byte[size];
        for (var i = 0; i < size; i++)
          data[i] = (byte)i;
        return new MemoryStream(data, false);
      }

      using var s = new ReadOnlyNestedStream(MakeStream(20), 3, 6);
      Assert.IsTrue(s.CanRead);
      Assert.IsTrue(s.CanSeek);
      Assert.IsFalse(s.CanWrite);
      Assert.AreEqual(0, s.Position);
      Assert.AreEqual(6, s.Length);

      var buf = CreateBuffer(3);
      Assert.AreEqual(3, s.Read(buf, 0, 3));
      Assert.AreEqual(new byte[] { 3, 4, 5 }, buf);
      Assert.AreEqual(3, s.Position);

      buf = CreateBuffer(5);
      Assert.AreEqual(3, s.Read(buf, 1, 3));
      Assert.AreEqual(new byte[] { 0xFF, 6, 7, 8, 0xFF }, buf);
      Assert.AreEqual(6, s.Position);

      Assert.AreEqual(0, s.Read(buf, 0, 3));
      Assert.AreEqual(6, s.Position);

      s.Position = 1;
      buf = CreateBuffer(9);
      Assert.AreEqual(5, s.Read(buf, 2, 6));
      Assert.AreEqual(new byte[] { 0xFF, 0xFF, 4, 5, 6, 7, 8, 0xFF, 0xFF }, buf);
      Assert.AreEqual(6, s.Position);

      s.Seek(2, SeekOrigin.Begin);
      Assert.AreEqual(2, s.Position);
      buf = CreateBuffer(3);
      Assert.AreEqual(3, s.Read(buf, 0, 3));
      Assert.AreEqual(new byte[] { 5, 6, 7 }, buf);
      Assert.AreEqual(5, s.Position);

      s.Seek(-2, SeekOrigin.Current);
      Assert.AreEqual(3, s.Position);
      buf = CreateBuffer(1);
      Assert.AreEqual(1, s.Read(buf, 0, 1));
      Assert.AreEqual(new byte[] { 6 }, buf);
      Assert.AreEqual(4, s.Position);

      s.Seek(-1, SeekOrigin.End);
      Assert.AreEqual(5, s.Position);
      buf = CreateBuffer(2);
      Assert.AreEqual(1, s.Read(buf, 0, 1));
      Assert.AreEqual(new byte[] { 8, 0xFF }, buf);
      Assert.AreEqual(6, s.Position);

      Assert.Throws<ArgumentOutOfRangeException>(() => s.Seek(-1, SeekOrigin.Begin));
      Assert.Throws<ArgumentOutOfRangeException>(() => s.Seek(0, (SeekOrigin)99));

      Assert.Throws<NotSupportedException>(() => s.Write(new byte[1], 0, 1));
      Assert.Throws<NotSupportedException>(() => s.SetLength(5));
      Assert.Throws<NotSupportedException>(s.Flush);
      Assert.Throws<ArgumentOutOfRangeException>(() => s.Position = -1);
      Assert.Throws<ArgumentOutOfRangeException>(() => s.Position = -1);
      Assert.Throws<ArgumentOutOfRangeException>(() => s.Position = s.Length + 1);
      Assert.Throws<ArgumentException>(() => _ = new ReadOnlyNestedStream(s, s.Length - 4, 5));
    }
  }
}