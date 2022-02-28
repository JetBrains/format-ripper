package com.jetbrains.util.filetype.elf

import com.jetbrains.util.*
import org.jetbrains.annotations.NotNull
import java.io.IOException
import java.nio.channels.SeekableByteChannel

object ElfUtil {
  fun GetElfInfo(@NotNull stream: SeekableByteChannel): ElfInfo {
    val reader = BinaryReader(stream.Rewind())
    try {
      if (reader.ReadUInt32Be() != 0x7F454C46u)
        error("Unknown format")

      val ei_class: ElfClass = when (reader.ReadByte().toInt()) {
        1 -> {
          ElfClass.ELFCLASS32
        }
        2 -> {
          ElfClass.ELFCLASS64
        }
        else ->
          error("Inconsistent ELF class")
      }

      val isBe: Boolean
      val ei_data: ElfData

      when (reader.ReadByte().toInt()) {
        1 -> {
          isBe = false
          ei_data = ElfData.ELFDATA2LSB
        }
        2 -> {
          isBe = true
          ei_data = ElfData.ELFDATA2MSB
        }
        else -> {
          error("Inconsistent ELF data")
        }
      }

      val version = ElfVersion.fromValue(reader.ReadByte())

      if (version != ElfVersion.EV_CURRENT)
        error("Inconsistent ELF version")

      val osabi = ElfOsAbi.fromValue(reader.ReadByte())
      val osAbiVersion = reader.ReadByte()
      val type: ElfType
      val machine: ElfMachine
      val flags: ULong
      var interpreter: String? = null

      stream.Seek(7, SeekOrigin.Current)// skip EI_PAD

      when (ei_class) {
        ElfClass.ELFCLASS32 -> {
          type = ElfType.fromValue(reader.ReadUInt16(isBe).toInt())
          machine = ElfMachine.fromValue(reader.ReadUInt16(isBe).toInt())
          val e_version32 = ElfVersion.fromValue(reader.ReadUInt32(isBe).toByte())

          if (e_version32 != ElfVersion.EV_CURRENT)
            error("Invalid version of ELF32 program header")

          stream.Seek(4, SeekOrigin.Current)// skip e_entry
          val ePhOff32 = reader.ReadUInt32(isBe)
          stream.Seek(4, SeekOrigin.Current)// skip e_shoff
          flags = reader.ReadUInt32(isBe).toULong()
          stream.Seek(2, SeekOrigin.Current)// skip e_ehsize
          val e_phentsize32 = reader.ReadUInt16(isBe)
          val ePhNum32 = reader.ReadUInt16(isBe)
          stream.Seek(ePhOff32.toLong(), SeekOrigin.Begin)
          var phi = ePhNum32.toInt()

          while (phi-- > 0) {
            val p_type = reader.ReadUInt32(isBe).toInt()

            if (p_type == ElfSegmentType.PT_INTERP) {
              val pOffset32 = reader.ReadUInt32(isBe)
              stream.Seek(8, SeekOrigin.Current)//skip p_vaddr, p_paddr
              val pFileSz32 = reader.ReadUInt32(isBe)
              stream.Seek(pOffset32.toLong(), SeekOrigin.Begin)
              interpreter = reader.ReadString(pFileSz32.toInt() - 1)
              break
            }
            stream.Seek(e_phentsize32.toLong() - 4, SeekOrigin.Current)
          }
        }
        ElfClass.ELFCLASS64 -> {
          type = ElfType.fromValue(reader.ReadUInt16(isBe).toInt())
          machine = ElfMachine.fromValue(reader.ReadUInt16(isBe).toInt())
          val e_version64 = ElfVersion.fromValue(reader.ReadUInt32(isBe).toByte())

          if (e_version64 != ElfVersion.EV_CURRENT)
            error("Invalid version of ELF64 program header")

          stream.Seek(8, SeekOrigin.Current)// skip e_entry
          val ePhOff64 = reader.ReadUInt64(isBe)
          stream.Seek(8, SeekOrigin.Current)// skip e_shoff
          flags = reader.ReadUInt32(isBe).toULong()
          stream.Seek(2, SeekOrigin.Current)// skip e_ehsize
          val e_phentsize64 = reader.ReadUInt16(isBe)
          val ePhNum64 = reader.ReadUInt16(isBe)
          stream.Seek(ePhOff64.toLong(), SeekOrigin.Begin)
          var phi = ePhNum64.toInt()

          while (phi-- > 0) {
            val p_type = reader.ReadUInt32(isBe).toInt()

            if (p_type == ElfSegmentType.PT_INTERP) {
              stream.Seek(4, SeekOrigin.Current)//skip p_flags
              val pOffset64 = reader.ReadUInt64(isBe)
              stream.Seek(16, SeekOrigin.Current)//skip p_vaddr, p_paddr
              val pFileSz64 = reader.ReadUInt64(isBe)
              stream.Seek(pOffset64.toLong(), SeekOrigin.Begin)
              interpreter = reader.ReadString(pFileSz64.toInt() - 1)
              break
            }
            stream.Seek(e_phentsize64.toLong() - 4, SeekOrigin.Current)
          }
        }
        else -> {
          error("Unknown ELF class")
        }
      }
      return ElfInfo(ei_class, ei_data, osabi, osAbiVersion, type, machine, flags, interpreter)
    } catch (ex: IOException) {
      error("Unknown format")
    }
  }
}
