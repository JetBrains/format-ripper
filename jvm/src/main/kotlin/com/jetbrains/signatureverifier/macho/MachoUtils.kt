package com.jetbrains.signatureverifier.macho

import com.jetbrains.util.BinaryReader
import com.jetbrains.util.ReadUInt32Le
import com.jetbrains.util.Seek
import com.jetbrains.util.SeekOrigin
import java.nio.channels.SeekableByteChannel

open class MachoUtils {
  companion object {
    // Note: See https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h
    // Note: See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

    fun IsFatMacho(magic: Long): Boolean =
      magic == MachoConsts.FAT_MAGIC || magic == MachoConsts.FAT_MAGIC_64 || magic == MachoConsts.FAT_CIGAM || magic == MachoConsts.FAT_CIGAM_64

    fun IsMacho(magic: Long): Boolean =
      magic == MachoConsts.MH_MAGIC || magic == MachoConsts.MH_MAGIC_64 || magic == MachoConsts.MH_CIGAM || magic == MachoConsts.MH_CIGAM_64

    fun ReadBlob(reader: BinaryReader): Pair<UInt, ByteArray> {
      val magic = reader.ReadUInt32Le(true)
      val length = reader.ReadUInt32Le(true)
      return magic to reader.ReadBytes(length.toInt())
    }

    fun ReadCodeDirectoryBlob(reader: BinaryReader): Pair<UInt, ByteArray> {
      val magic = reader.ReadUInt32Le(true)
      val length = reader.ReadUInt32Le(true)
      (reader.BaseStream as SeekableByteChannel).Seek(-8, SeekOrigin.Current)
      return magic to reader.ReadBytes(length.toInt())
    }
  }
}

