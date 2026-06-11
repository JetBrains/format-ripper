using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum SHT : uint
  {
    // @formatter:off
    SHT_NULL          =          0, // Section header table entry unused
    SHT_PROGBITS      =          1, // Program data
    SHT_SYMTAB        =          2, // Symbol table
    SHT_STRTAB        =          3, // String table
    SHT_RELA          =          4, // Relocation entries with addends
    SHT_HASH          =          5, // Symbol hash table
    SHT_DYNAMIC       =          6, // Dynamic linking information
    SHT_NOTE          =          7, // Notes
    SHT_NOBITS        =          8, // Program space with no data (bss)
    SHT_REL           =          9, // Relocation entries, no addends
    SHT_SHLIB         =         10, // Reserved
    SHT_DYNSYM        =         11, // Dynamic linker symbol table
    SHT_INIT_ARRAY    =         14, // Array of constructors
    SHT_FINI_ARRAY    =         15, // Array of destructors
    SHT_PREINIT_ARRAY =         16, // Array of pre-constructors
    SHT_GROUP         =         17, // Section group
    SHT_SYMTAB_SHNDX  =         18, // Extended section indices
    SHT_RELR          =         19, // RELR relative relocations
    SHT_NUM           =         20, // Number of defined types

    SHT_LOOS          = 0x60000000, // Start of OS-specific

    SHT_GNU_ATTRIBUTES= 0x6ffffff5, // Object attributes
    SHT_GNU_HASH      = 0x6ffffff6, // GNU-style hash table
    SHT_GNU_LIBLIST   = 0x6ffffff7, // Prelink library list
    SHT_CHECKSUM      = 0x6ffffff8, // Checksum for DSO content

    SHT_LOSUNW        = 0x6ffffffa, // Sun-specific low bound
    SHT_SUNW_move     = 0x6ffffffa,
    SHT_SUNW_COMDAT   = 0x6ffffffb,
    SHT_SUNW_syminfo  = 0x6ffffffc,
    SHT_HISUNW        = 0x6fffffff, // Sun-specific high bound

    SHT_GNU_verdef    = 0x6ffffffd, // Version definition section
    SHT_GNU_verneed   = 0x6ffffffe, // Version needs section
    SHT_GNU_versym    = 0x6fffffff, // Version symbol table

    SHT_HIOS          = 0x6fffffff, // End of OS-specific type

    SHT_LOPROC        = 0x70000000, // Start of processor-specific
    SHT_ARM_EXIDX     = 0x70000001, // ARM exception index table
    SHT_ARM_PREEMPTMAP= 0x70000002, // ARM BPABI DLL dynamic linking pre-emption map
    SHT_ARM_ATTRIBUTES= 0x70000003, // ARM object file compatibility attributes
    SHT_ARM_DEBUGOVERLAY = 0x70000004, // ARM debug overlay
    SHT_ARM_OVERLAYSECTION = 0x70000005, // ARM overlay section
    SHT_MIPS_REGINFO  = 0x70000006, // MIPS .reginfo section (register usage information)
    SHT_MIPS_OPTIONS  = 0x7000000d, // MIPS .MIPS.options section (ABI/options; ELF64 analog of .reginfo)
    SHT_MIPS_ABIFLAGS = 0x7000002a, // MIPS .MIPS.abiflags section (ABI/FP requirements)
    SHT_HIPROC        = 0x7fffffff, // End of processor-specific

    SHT_LOUSER        = 0x80000000, // Start of application-specific
    SHT_HIUSER        = 0x8fffffff  // End of application-specific
    // @formatter:on
  }
}
