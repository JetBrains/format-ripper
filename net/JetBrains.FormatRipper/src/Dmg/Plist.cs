using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace JetBrains.FormatRipper.Dmg;

public class Plist
{
  internal static List<String> GetDataByKey(XDocument document, String keyName)
  {
    List<String> result = new List<string>();
    foreach (var key in document.Descendants("key"))
    {
      if (key.Value == keyName)
      {
        using var nextElementsEnumerator = key.ElementsAfterSelf().GetEnumerator();
        if (nextElementsEnumerator.MoveNext())
          result.Add(nextElementsEnumerator.Current.Value);
      }
    }

    return result;
  }
}