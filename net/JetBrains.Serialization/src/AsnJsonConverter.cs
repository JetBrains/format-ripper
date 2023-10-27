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

        default:
          writer.WriteStartObject();
          writer.WritePropertyName("type");
          writer.WriteValue(TextualInfo.GetType(asnValue));

          writer.WritePropertyName("value");
          writer.WriteValue(TextualInfo.GetStringValue(asnValue));
          writer.WriteEndObject();
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
      case JTokenType.Array:
        return jsonToken.Select(it => ConvertObject(it.Value<JToken>())).ToDerSet();
      case JTokenType.Object:
        var properties = ((JObject)jsonToken).Properties().ToList();
        switch (properties[0].Name)
        {
          case "type":
            if (properties.Count != 2)
              throw new Exception();
            return TextualInfo.GetEncodable(properties[0].Value.ToString(), properties[1].Value.ToString())
              .ToAsn1Object();
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