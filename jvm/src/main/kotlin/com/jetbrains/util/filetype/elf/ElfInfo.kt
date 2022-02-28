package com.jetbrains.util.filetype.elf

class ElfInfo(
  val ElfClass: ElfClass,
  val Data: ElfData,
  val OsAbi: ElfOsAbi,
  val OsAbiVersion: Byte,
  val Type: ElfType,
  val Machine: ElfMachine,
  val Flags: ULong,
  val Interpreter: String?
)
