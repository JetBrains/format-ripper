package com.jetbrains.signatureverifier.serialization

import java.math.BigInteger

data class SignerIdentifierInfo (
  val issuerInfo: IssuerInfo,
  val serialNumber: BigInteger
)
