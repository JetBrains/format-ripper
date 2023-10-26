using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

public class AsnJsonConverter : JsonConverter
{
  public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
  {
    if (value is Asn1Object)
    {
      writer.WriteStartObject();

      switch (value)
      {
        case Asn1TaggedObject taggedObject:
          writer.WritePropertyName("type");
          writer.WriteValue("TAGGED");

          writer.WritePropertyName("explicit");
          writer.WriteValue(taggedObject.IsExplicit());

          writer.WritePropertyName("tagNo");
          writer.WriteValue(taggedObject.TagNo);

          writer.WritePropertyName("object");
          serializer.Serialize(writer, taggedObject.GetObject().ToAsn1Object());
          break;

        case Asn1Sequence sequence:
          writer.WritePropertyName("type");
          writer.WriteValue("SEQ");

          writer.WritePropertyName("content");
          serializer.Serialize(writer,
            sequence
              .ToArray()
              .Select(item => item.ToAsn1Object())
              .ToList());
          break;

        case Asn1Set set:
          writer.WritePropertyName("type");
          writer.WriteValue("SET");

          writer.WritePropertyName("content");
          serializer.Serialize(writer,
            set
              .ToArray()
              .Select(item => item.ToAsn1Object())
              .ToList());
          break;

        default:
          writer.WritePropertyName("type");
          writer.WriteValue(value.GetType().Name);
          writer.WritePropertyName("value");
          writer.WriteValue(value.ToString());
          break;
      }

      writer.WriteEndObject();
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

  public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
  {
    throw new NotImplementedException();
  }

  public override bool CanConvert(Type objectType)
  {
    return typeof(Asn1Object).IsAssignableFrom(objectType) ||
           typeof(ICollection<Asn1Object>).IsAssignableFrom(objectType);
  }
}