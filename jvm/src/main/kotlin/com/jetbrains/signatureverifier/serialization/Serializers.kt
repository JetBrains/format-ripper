package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.*
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Null
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DLTaggedObject

@OptIn(ExperimentalSerializationApi::class)
@Serializer(forClass = ASN1Primitive::class)
object Asn1PrimitiveSerializer : KSerializer<ASN1Primitive> {
  override val descriptor = ContextualSerializer(ASN1Primitive::class).descriptor

  override fun deserialize(decoder: Decoder): ASN1Primitive {
    val jsonInput = decoder as? JsonDecoder ?: throw SerializationException("Only JSON format is supported")
    return when (val jsonElement = jsonInput.decodeJsonElement()) {
      is JsonObject -> {
        if ("explicit" in jsonElement && "tagNo" in jsonElement && "object" in jsonElement) {
          if (jsonElement.keys.count() != 3) {
            throw SerializationException("Incorrect number of fields for tagged object: ${jsonElement.keys.count()}, expected 3")
          }
          val explicit =
            jsonElement["explicit"]?.jsonPrimitive?.boolean
              ?: throw SerializationException("\"Explicit\" is missing for tagged object")
          val tagNo = jsonElement["tagNo"]?.jsonPrimitive?.int
            ?: throw SerializationException("\"TagNo\" is missing for tagged object")
          val obj = Json.decodeFromJsonElement(
            Asn1PrimitiveSerializer,
            jsonElement["object"] ?: throw SerializationException("\"Object\" is missing for tagged object")
          )
          DLTaggedObject(explicit, tagNo, obj)
        } else {
          var c = 0
          val elements = jsonElement.map { (i, json) ->
            if (i.toIntOrNull() != c) {
              throw SerializationException("Illegal index for sequence: ${i.toIntOrNull()}, expected $c")
            }
            c++
            Json.decodeFromJsonElement(Asn1PrimitiveSerializer, json)
          }
          elements.toDLSequence()
        }
      }

      is JsonArray -> {
        val elements = jsonElement.map { json ->
          Json.decodeFromJsonElement(Asn1PrimitiveSerializer, json)
        }
        elements.toDLSet()
      }

      is JsonNull -> {
        DERNull.INSTANCE
      }

      is JsonPrimitive -> {
        if (jsonElement.isString) {
          val value = jsonElement.toString().substringAfter('"').substringBeforeLast('"')
          val tagEnd = value.indexOf(']')

          if (value[0] != '[' || tagEnd < 0) {
            throw SerializationException("Could not parse tag for entry $jsonElement")
          }

          val tag = value.substring(1, tagEnd)

          val textualValue = value.substring(tagEnd + 2)

          TextualInfo.getPrimitive(tag, textualValue)
        } else {

          return ASN1Boolean.getInstance(
            jsonElement.booleanOrNull ?: throw SerializationException("Unsupported ASN1Primitive type: $jsonElement")
          )
        }
      }

      else -> throw SerializationException("Unsupported JSON element type")
    }
  }

  @OptIn(ExperimentalSerializationApi::class)
  override fun serialize(encoder: Encoder, value: ASN1Primitive) {
    val jsonOutput = encoder as? JsonEncoder
      ?: throw SerializationException("Only JSON format is supported")

    when (value) {
      is ASN1TaggedObject -> {
        jsonOutput.encodeJsonElement(buildJsonObject {
          put("explicit", value.isExplicit)
          put("tagNo", value.tagNo)
          put("object", Json.encodeToJsonElement(Asn1PrimitiveSerializer, value.baseObject.toASN1Primitive()))
        })
      }

      is ASN1Sequence -> {
        jsonOutput.encodeJsonElement(buildJsonObject {
          value.forEachIndexed { index, item ->
            put(index.toString(), Json.encodeToJsonElement(Asn1PrimitiveSerializer, item.toASN1Primitive()))
          }
        })
      }

      is ASN1Set -> {
        jsonOutput.encodeJsonElement(buildJsonArray {
          value.forEach { item ->
            add(Json.encodeToJsonElement(Asn1PrimitiveSerializer, item.toASN1Primitive()))
          }
        })
      }

      is ASN1Null -> {
        jsonOutput.encodeJsonElement(JsonNull)
      }

      is ASN1Boolean -> {
        jsonOutput.encodeJsonElement(JsonPrimitive(value.isTrue))
      }

      else -> {
        jsonOutput.encodeJsonElement(
          JsonPrimitive(
            TextualInfo.getTaggedValue(value)
          )
        )
      }
    }
  }
}