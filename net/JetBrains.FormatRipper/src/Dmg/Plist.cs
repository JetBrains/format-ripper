using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml.Linq;

namespace JetBrains.FormatRipper.Dmg;

public class Plist
{
  internal static List<XElement> GetDataByKey(XElement document, string keyName)
  {
    List<XElement> result = new List<XElement>();
    foreach (var node in GetNodesByKey(document, keyName))
    {
      using var nextElementsEnumerator = node.ElementsAfterSelf().GetEnumerator();
      if (nextElementsEnumerator.MoveNext())
        result.Add(nextElementsEnumerator.Current);
    }

    return result;
  }

  internal static List<XElement> GetNodesByKey(XElement document, string keyName)
  {
    List<XElement> result = new List<XElement>();
    foreach (var key in document.Descendants("key"))
    {
      if (key.Value == keyName)
      {
        result.Add(key);
      }
    }

    return result;
  }

  internal static List<BLKXEntry> ParseBlkxArray(XDocument document)
  {
    List<BLKXEntry> result = new List<BLKXEntry>();


    if (document.Root == null)
      return result;
    var array = GetDataByKey(document.Root, "blkx")[0];
    if (array == null)
      return result;

    foreach (var dict in array.Descendants("dict"))
    {
      var attributes = GetDataByKey(dict, "Attributes")[0].Value;
      var cfName = GetDataByKey(dict, "CFName")[0].Value;

      var data = GetDataByKey(dict, "Data")[0].Value;
      var s = data.Replace("\n", string.Empty).Replace("\t", string.Empty);
      var bytes = Convert.FromBase64String(s);

      using MemoryStream mishStream = new MemoryStream(bytes);
      using BinaryReader reader = new BinaryReader(mishStream,
        BitConverter.IsLittleEndian ? Encoding.Unicode : Encoding.BigEndianUnicode);
      var mishBlock = new MishBlock(reader);

      var id = GetDataByKey(dict, "ID")[0].Value;
      var name = GetDataByKey(dict, "Name")[0].Value;

      result.Add(new BLKXEntry(attributes, cfName, mishBlock, id, name));
    }

    return result;
  }
}