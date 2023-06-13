package com.jetbrains.signatureverifier.serialization

data class SignerInformation(
  val version: Int,
  val sid: SignerIdentifierInfo,
  val digestAlgorithm: SignatureAlgorithmInfo,
  val authenticatedAttributes: List<AttributeInfo>
)


