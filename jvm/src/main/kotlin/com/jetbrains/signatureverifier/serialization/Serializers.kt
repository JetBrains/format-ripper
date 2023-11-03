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
    val jsonElement = jsonInput.decodeJsonElement()

    return when (jsonElement) {
      is JsonObject -> {
        if ("explicit" in jsonElement && "tagNo" in jsonElement && "object" in jsonElement) {
          val explicit = jsonElement["explicit"]!!.jsonPrimitive.boolean
          val tagNo = jsonElement["tagNo"]!!.jsonPrimitive.int
          val obj = Json.decodeFromJsonElement(Asn1PrimitiveSerializer, jsonElement["object"]!!)
          DLTaggedObject(explicit, tagNo, obj)
        } else {
          val elements = jsonElement.map { (_, json) ->
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
          val tag = value.substring(1, tagEnd)

          val textualValue = value.substring(tagEnd + 2)

          TextualInfo.getPrimitive(tag, textualValue)
        } else {

          return ASN1Boolean.getInstance(
            jsonElement.booleanOrNull ?: throw SerializationException("Unsupported ASN1Primitive type")
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
        jsonOutput.encodeJsonElement(JsonPrimitive("[${TextualInfo.getType(value)}] ${TextualInfo.getStringValue(value)}"))
      }
    }
  }
}