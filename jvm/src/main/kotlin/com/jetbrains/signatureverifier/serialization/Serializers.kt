package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import kotlinx.serialization.json.Json.Default.encodeToJsonElement
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Null
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject

//object AsnSerializer : JsonContentPolymorphicSerializer<ASN1Primitive>(ASN1Primitive::class) {
//  override fun selectDeserializer(element: JsonElement) = when {
//    "cardName" in element.jsonObject -> CreditCardPaymentDetails.serializer()
//    else -> StandardPaymentDetails.serializer()
//  }
//}

@OptIn(ExperimentalSerializationApi::class)
@Serializer(forClass = ASN1Primitive::class)
object Asn1PrimitiveSerializer : KSerializer<ASN1Primitive> {
  override val descriptor = ContextualSerializer(ASN1Primitive::class).descriptor

  override fun deserialize(decoder: Decoder): ASN1Sequence {
    TODO("Not yet implemented")
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

//@OptIn(ExperimentalSerializationApi::class)
//@Serializer(forClass = ASN1Sequence::class)
//object Asn1SequenceSerializer : KSerializer<ASN1Sequence> {
//  @OptIn(ExperimentalSerializationApi::class)
//  override val descriptor = ContextualSerializer(ASN1Primitive::class).descriptor
//
//  override fun deserialize(decoder: Decoder): ASN1Sequence {
//    TODO("Not yet implemented")
//  }
//
//  override fun serialize(encoder: Encoder, value: ASN1Sequence) {
//    val jsonOutput = encoder as? JsonEncoder
//      ?: throw SerializationException("Only JSON format is supported")
//
//    val content = value.toList().map { it.toASN1Primitive() }
//
//    jsonOutput.encodeJsonElement(buildJsonObject {
//      content.forEachIndexed { index, item ->
//        put(index.toString(), Json.encodeToJsonElement(Asn1PrimitiveSerializer, item))
//      }
//    })
//  }
//}