using System.Runtime.Serialization;
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
          writer.WriteValue(TextualInfo.GetTaggedValue(asnValue));
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
              throw new SerializationException(
                $"Incorrect number of fields for tagged object: {properties.Count}, expected 3");
            }

            if (properties[0].Value.Type != JTokenType.Boolean)
            {
              throw new SerializationException(
                $"Illegal value for Explicit in tagged object");
            }

            if (properties[1].Name != "tagNo" || properties[1].Value.Type != JTokenType.Integer)
            {
              throw new SerializationException(
                "Illegal TagNo in tagged object");
            }

            if (properties[2].Name != "object")
            {
              throw new SerializationException(
                "Illegal Object in tagged object");
            }

            return new DerTaggedObject((bool)properties[0], (int)properties[1],
              ConvertObject(properties[2].Value));

          default:
            int c = 0;
            return properties.Select(it =>
              {
                if (!(int.TryParse(it.Name, out _) && int.Parse(it.Name) == c))
                {
                  throw new SerializationException($"Illegal index in sequence: {it.Name}, expected {c}");
                }

                c++;

                return ConvertObject(it.Value);
              }
            ).ToDerSequence();
        }
      case JTokenType.String:
        var token = jsonToken.ToString();

        var tagEndIndex = token.IndexOf("]", StringComparison.Ordinal);

        if (token[0] != '[' || tagEndIndex < 0)
        {
          throw new SerializationException($"Could not parse tag for entry {token}");
        }

        var type = token.Substring(1, tagEndIndex - 1);

        if (tagEndIndex + 2 > token.Length)
        {
          throw new SerializationException($"Could not parse value for entry {token}");
        }

        var value = token.Substring(tagEndIndex + 2);

        return TextualInfo.GetEncodable(type, value)
          .ToAsn1Object();
    }

    throw new SerializationException("Could not parse give json");
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