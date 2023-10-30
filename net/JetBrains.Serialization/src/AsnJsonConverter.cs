using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

public class AsnJsonConverter : JsonConverter
{
  public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
  {
    if (value is Asn1Object asnValue)
    {
      switch (value)
      {
        case Asn1TaggedObject taggedObject:
          writer.WriteStartObject();

          writer.WritePropertyName("explicit");
          writer.WriteValue(taggedObject.IsExplicit());

          writer.WritePropertyName("tagNo");
          writer.WriteValue(taggedObject.TagNo);

          writer.WritePropertyName("object");
          serializer.Serialize(writer, taggedObject.GetObject().ToAsn1Object());
          writer.WriteEndObject();
          break;

        case Asn1Sequence sequence:
          writer.WriteStartObject();

          var content = sequence
            .ToArray()
            .Select(item => item.ToAsn1Object())
            .ToList();

          for (int i = 0; i < content.Count; i++)
          {
            writer.WritePropertyName(i.ToString());
            serializer.Serialize(writer, content[i]);
          }

          writer.WriteEndObject();
          break;

        case Asn1Set set:
          serializer.Serialize(writer,
            set
              .ToArray()
              .Select(item => item.ToAsn1Object())
              .ToList());
          break;

        case DerNull:
          writer.WriteNull();
          break;

        case DerBoolean boolean:
          writer.WriteValue(boolean.IsTrue);
          break;

        default:
          writer.WriteValue("[" + TextualInfo.GetType(asnValue) + "] " + TextualInfo.GetStringValue(asnValue));
          break;
      }
    }
    else if (value is List<Asn1Object> list)
    {
      writer.WriteStartArray();

      foreach (var asn1Object in list)
      {
        serializer.Serialize(writer, asn1Object);
      }

      writer.WriteEndArray();
    }
  }


  private Asn1Object ConvertObject(JToken? jsonToken)
  {
    if (jsonToken == null)
    {
      return DerNull.Instance;
    }

    switch (jsonToken.Type)
    {
      case JTokenType.Null:
        return DerNull.Instance;
      case JTokenType.Boolean:
        return jsonToken.Value<bool>() ? DerBoolean.True : DerBoolean.False;
      case JTokenType.Array:
        return jsonToken.Select(it => ConvertObject(it.Value<JToken>())).ToDerSet();
      case JTokenType.Object:
        var properties = ((JObject)jsonToken).Properties().ToList();
        switch (properties[0].Name)
        {
          case "explicit":
            if (properties.Count != 3)
            {
              throw new Exception();
            }

            return new DerTaggedObject((bool)properties[0].Value, (int)properties[1].Value,
              ConvertObject(properties[2].Value));

          default:
            return properties.Select(it => ConvertObject(it.Value)).ToDerSequence();
        }
      case JTokenType.String:
        var token = jsonToken.ToString();
        if (token[0] != '[')
        {
          throw new FormatException();
        }

        var tagEndIndex = token.IndexOf("]", StringComparison.Ordinal);
        var type = token.Substring(1, tagEndIndex - 1);

        if (tagEndIndex + 2 > token.Length)
        {
          throw new FormatException();
        }

        var value = token.Substring(tagEndIndex + 2);

        return TextualInfo.GetEncodable(type, value)
          .ToAsn1Object();
    }

    return DerNull.Instance;
  }

  public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
  {
    JObject jsonObject = JObject.Load(reader);
    return ConvertObject(jsonObject);
  }

  public override bool CanConvert(Type objectType)
  {
    return typeof(Asn1Object).IsAssignableFrom(objectType) ||
           typeof(ICollection<Asn1Object>).IsAssignableFrom(objectType);
  }
}