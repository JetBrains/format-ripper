package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.math.BigInteger
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter
import java.util.*

object DateSerializer : KSerializer<Date> {
  private val df: DateFormat = SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSS")

  override fun serialize(encoder: Encoder, value: Date) =
    encoder.encodeString(df.format(value))


  override fun deserialize(decoder: Decoder): Date = df.parse(decoder.decodeString())


  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("Date", PrimitiveKind.STRING)
}


object OffsetDateTimeSerializer : KSerializer<OffsetDateTime> {
  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("OffsetDateTime", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: OffsetDateTime) {
    val format = DateTimeFormatter.ISO_OFFSET_DATE_TIME

    val string = format.format(value)
    encoder.encodeString(string)
  }

  override fun deserialize(decoder: Decoder): OffsetDateTime =
    OffsetDateTime.parse(decoder.decodeString())
}

object BigIntegerSerializer : KSerializer<BigInteger> {
  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("BigInteger", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: BigInteger) =
    encoder.encodeString(value.toString())


  override fun deserialize(decoder: Decoder): BigInteger = decoder.decodeString().toBigInteger()
}

object ByteArraySerializer : KSerializer<ByteArray> {
  override fun serialize(encoder: Encoder, value: ByteArray) =
    encoder.encodeString(value.toHexString())

  override fun deserialize(decoder: Decoder): ByteArray =
    decoder.decodeString().toByteArray()


  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("HexByteArray", PrimitiveKind.STRING)
}