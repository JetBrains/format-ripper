package com.jetbrains.signatureverifier.serialization

data class SignerInformation(
  val version: Int,
  val sid: SignerIdentifierInfo,
  val digestAlgorithm: SignatureAlgorithm,
  val authenticatedAttributes: List<AttributeInfo>
)


