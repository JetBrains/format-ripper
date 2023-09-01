package com.jetbrains.util.filetype

import com.jetbrains.util.*
import java.io.IOException
import java.nio.channels.SeekableByteChannel
import java.util.*

object FileTypeDetector {
  fun SeekableByteChannel.DetectFileType(): Pair<FileType, EnumSet<FileProperties>> {
    var res = IsPe(this)
    if (res != null)
      return FileType.Pe to res

    res = IsMsi(this)
    if (res != null)
      return FileType.Msi to res

    res = TryParseMachO(this)?.first
    if (res != null)
      return FileType.MachO to res

    res = IsElf(this)
    if (res != null)
      return FileType.Elf to res

    res = IsShebangScript(this)
    if (res != null)
      return FileType.ShebangScript to res

    return FileType.Unknown to enumSetOf(FileProperties.UnknownType)
  }

  private fun IsPe(stream: SeekableByteChannel): EnumSet<FileProperties>? {
    try {
      val reader = BinaryReader(stream.Rewind())

      if (reader.ReadUInt16().toInt() != 0x5A4D) // IMAGE_DOS_SIGNATURE
        return null

      stream.Seek(0x3C, SeekOrigin.Begin) // IMAGE_DOS_HEADER::e_lfanew
      stream.Seek(reader.ReadUInt32().toLong(), SeekOrigin.Begin)
      if (reader.ReadUInt32().toInt() != 0x00004550) // IMAGE_NT_SIGNATURE
        return null
      stream.Seek(0x12, SeekOrigin.Current) // IMAGE_FILE_HEADER::Characteristics

      val fileProperties = enumSetOf(
        when (reader.ReadUInt16().toInt() and 0x2002) {
          0x2002 -> FileProperties.SharedLibraryType // IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL
          0x0002 -> FileProperties.ExecutableType // IMAGE_FILE_EXECUTABLE_IMAGE
          else -> FileProperties.UnknownType
        }
      )

      when (reader.ReadUInt16().toInt()) // IMAGE_OPTIONAL_HEADER32::Magic / IMAGE_OPTIONAL_HEADER64::Magic
      {
        // IMAGE_NT_OPTIONAL_HDR32_MAGIC
        0x10b -> stream.Seek(
          0x60L - UShort.SIZE_BYTES,
          SeekOrigin.Current
        ) // Skip IMAGE_OPTIONAL_HEADER32 to DataDirectory
        // IMAGE_NT_OPTIONAL_HDR64_MAGIC
        0x20b -> stream.Seek(
          0x70L - UShort.SIZE_BYTES,
          SeekOrigin.Current
        ) // Skip IMAGE_OPTIONAL_HEADER64 to DataDirectory
        else -> null
      }

      stream.Seek(Long.SIZE_BYTES * 4L, SeekOrigin.Current) // DataDirectory + IMAGE_DIRECTORY_ENTRY_SECURITY
      val securityRva = reader.ReadUInt32()
      val securitySize = reader.ReadUInt32()

      if (securityRva.toInt() != 0 && securitySize.toInt() != 0)
        fileProperties += FileProperties.Signed

      stream.Seek(Long.SIZE_BYTES * 9L, SeekOrigin.Current) // DataDirectory + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
      val comRva = reader.ReadUInt32()
      val comSize = reader.ReadUInt32()

      if (comRva.toInt() != 0 && comSize.toInt() != 0)
        fileProperties += FileProperties.Managed

      return fileProperties
    } catch (ex: IOException) {
      return null
    }
  }

  private fun IsMsi(stream: SeekableByteChannel): EnumSet<FileProperties>? {
    // Note: Object Linking and Embedding (OLE) Compound File (CF) (i.e., OLECF) or Compound Binary File format by Microsoft
    try {
      val reader = BinaryReader(stream.Rewind())

      //OLE CH magic 0xE11AB1A1E011CFD0
      if (reader.ReadInt64() != -2226271756974174256)
        return null
      return enumSetOf(FileProperties.UnknownType)
    } catch (ex: IOException) {
      return null
    }
  }

  private fun IsElf(stream: SeekableByteChannel): EnumSet<FileProperties>? {
    try {
      val reader = BinaryReader(stream.Rewind())

      // Note: See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

      if (reader.ReadUInt32() != 0x464C457Fu) // e_ident[EI_MAG0..EI_MAG3]
        return null

      val is64 = when (reader.ReadByte().toInt()) // e_ident[EI_CLASS]
      {
        1 -> false
        2 -> true
        else -> return null
      }

      val isBe = when (reader.ReadByte().toInt()) // e_ident[EI_DATA]
      {
        1 -> false
        2 -> true
        else -> return null
      }

      if (reader.ReadByte().toInt() != 1) // e_ident[EI_VERSION]
        return null

      stream.Seek(9, SeekOrigin.Current)
      val eType = reader.ReadUInt16Le(isBe) // e_type
      stream.Seek(2, SeekOrigin.Current)

      if (reader.ReadUInt32Le(isBe) != 1u) // e_version
        return null

      when (eType.toInt()) {
        0x02 -> return enumSetOf(FileProperties.ExecutableType) // ET_EXEC
        0x03 -> Unit // ET_DYN
        else -> return enumSetOf(FileProperties.UnknownType)
      }

      stream.Seek(if (is64) 8 else 4, SeekOrigin.Current)
      val ePhOff = if (is64) reader.ReadUInt64Le(isBe) else reader.ReadUInt32Le(isBe).toULong() // e_phoff

      stream.Seek(if (is64) 0x10 else 0xC, SeekOrigin.Current)
      var ePhNum = reader.ReadUInt16Le(isBe).toInt() // e_phnum

      stream.Seek(ePhOff.toLong(), SeekOrigin.Begin)

      var hasExecutable = false

      while (ePhNum-- > 0) {
        if (reader.ReadUInt32Le(isBe) == 0x00000003u) // PT_INTERP
          hasExecutable = true
        stream.Seek(if (is64) 0x34 else 0x1C, SeekOrigin.Current)
      }

      return if (hasExecutable)
        enumSetOf(FileProperties.ExecutableType)
      else
        enumSetOf(FileProperties.SharedLibraryType)
    } catch (ex: IOException) {
      return null
    }
  }

  private fun TryParseMachO(stream: SeekableByteChannel): Pair<EnumSet<FileProperties>, List<ProcessorArchitecture>>? {
    try {
      val reader = BinaryReader(stream.Rewind())

      fun ReadHeader(magic: Long): Pair<EnumSet<FileProperties>, List<ProcessorArchitecture>>? {
        // Note: See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

        val isLe32 = magic == 0xFEEDFACE // MH_MAGIC
        val isLe64 = magic == 0xFEEDFACF // MH_MAGIC_64
        val isBe32 = magic == 0xCEFAEDFE // MH_CIGAM
        val isBe64 = magic == 0xCFFAEDFE // MH_CIGAM_64

        if (isLe32 || isLe64 || isBe32 || isBe64) {
          // Machine types:
          val CPU_ARCH_ABI64 = 0x01000000
          val CPU_TYPE_X86 = 7
          val CPU_TYPE_X86_64 = CPU_TYPE_X86 or CPU_ARCH_ABI64
          val CPU_TYPE_ARM64 = 12 or CPU_ARCH_ABI64

          val cputype =
            when (reader.ReadUInt32Le(isBe32 || isBe64).toInt())  // mach_header::cputype / mach_header_64::cputype
            {
              CPU_TYPE_X86 -> ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL // CPU_TYPE_X86
              CPU_TYPE_X86_64 -> ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64 // CPU_TYPE_X86_64
              CPU_TYPE_ARM64 -> ProcessorArchitecture.PROCESSOR_ARCHITECTURE_ARM64 // CPU_TYPE_ARM64
              else -> ProcessorArchitecture.PROCESSOR_ARCHITECTURE_UNKNOWN
            }

          stream.Seek(4, SeekOrigin.Current)

          val fileProperties = enumSetOf(
            when (reader.ReadUInt32Le(isBe32 || isBe64).toInt()) // mach_header::filetype / mach_header_64::filetype
            {
              0x2 -> FileProperties.ExecutableType // MH_EXECUTE
              0x6 -> FileProperties.SharedLibraryType // MH_DYLIB
              0x8 -> FileProperties.BundleType // MH_BUNDLE
              else -> FileProperties.UnknownType
            }
          )

          var ncmds = reader.ReadUInt32Le(isBe32 || isBe64).toInt() // mach_header::ncmds / mach_header_64::ncmds
          stream.Seek(if (isLe64 || isBe64) 0xC else 0x8, SeekOrigin.Current) // load_command[0]

          while (ncmds-- > 0) {
            val cmd = reader.ReadUInt32Le(isBe32 || isBe64) // load_command::cmd
            val cmdsize = reader.ReadUInt32Le(isBe32 || isBe64) // load_command::cmdsize
            stream.Seek((cmdsize - 8u).toLong(), SeekOrigin.Current)

            if (cmd == 0x1Du) // LC_CODE_SIGNATURE
              fileProperties += FileProperties.Signed
          }

          return fileProperties to listOf(cputype)
        }
        return null
      }

      fun ReadFatHeader(magic: Long): Pair<EnumSet<FileProperties>, List<ProcessorArchitecture>>? {
        // Note: See https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h

        val isLe32 = magic == 0xCAFEBABE // FAT_MAGIC
        val isLe64 = magic == 0xCAFEBABF // FAT_MAGIC_64
        val isBe32 = magic == 0xBEBAFECA // FAT_CIGAM
        val isBe64 = magic == 0xBFBAFECA // FAT_CIGAM_64

        if (isLe32 || isLe64 || isBe32 || isBe64) {
          var nFatArch = reader.ReadUInt32Le(isBe32 || isBe64).toInt() // fat_header ::nfat_arch
          val offsets = mutableListOf<ULong>()

          if (isBe64 || isLe64)
            while (nFatArch-- > 0) {
              stream.Seek(8, SeekOrigin.Current)
              offsets.add(reader.ReadUInt64Le(isBe64)) // fat_arch_64::offset
              stream.Seek(16, SeekOrigin.Current)
            }
          else
            while (nFatArch-- > 0) {
              stream.Seek(8, SeekOrigin.Current)
              offsets.add(reader.ReadUInt32Le(isBe32).toULong()) // fat_arch::offset
              stream.Seek(8, SeekOrigin.Current)
            }

          val fileArchitecturesList = mutableListOf<ProcessorArchitecture>()

          val filePropertiesList = offsets.map { offset ->
            stream.Seek(offset.toLong(), SeekOrigin.Begin)
            val fileProperties = ReadHeader(reader.ReadUInt32().toLong()) // mach_header::magic / mach_header64::magic
            if (fileProperties != null)
              fileArchitecturesList.add(fileProperties.second[0])
            fileProperties?.first
          }

          if (filePropertiesList.isEmpty())
            return enumSetOf(FileProperties.UnknownType) to listOf()

          // One of headers is invalid
          if (filePropertiesList.any { x -> x == null })
            return null

          val signed = filePropertiesList.all {
            it != null && it.contains(FileProperties.Signed)
          }
          if (filePropertiesList.asSequence().filterNotNull().map {
              if (signed) it else {
                // One binary in MultiArch file is not signed
                it - FileProperties.Signed
              }
            }.distinct().count() > 1
          ) {
            // Headers are incompatible
            return null
          }

          val totalFileProperty = filePropertiesList[0]

          if (filePropertiesList.count() > 1)
            if (totalFileProperty != null) {
              totalFileProperty += FileProperties.MultiArch
              if (!signed) {
                totalFileProperty -= FileProperties.Signed
              }
            }

          return totalFileProperty!! to fileArchitecturesList
        }

        return null
      }

      val masterMagic = reader.ReadUInt32().toLong() // mach_header::magic / mach_header64::magic / fat_header::magic
      return ReadFatHeader(masterMagic) ?: ReadHeader(masterMagic)
    } catch (ex: IOException) {
      return null
    }
  }

  private fun IsShebangScript(stream: SeekableByteChannel): EnumSet<FileProperties>? {
    try {
      val reader = BinaryReader(stream.Rewind())

      if (reader.ReadByte().toInt().toChar() == '#' && reader.ReadByte().toInt().toChar() == '!') {
        var c = reader.ReadByte().toInt().toChar()
        while (c == ' ' || c == '\t')
          c = reader.ReadByte().toInt().toChar()
        if (c == '/')
          return enumSetOf(FileProperties.ExecutableType)
      }
      return null
    } catch (ex: IOException) {
      return null
    }
  }

  private inline fun <reified T : Enum<T>?> enumSetOf(vararg items: T): EnumSet<T> {
    return EnumSet.noneOf(T::class.java).apply { addAll(items) }
  }
}

