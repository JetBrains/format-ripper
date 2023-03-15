using System;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Elf.Impl;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Elf
{
  public sealed class ElfFile
  {
    public readonly EF EFlags;
    public readonly byte EiAbiVersion;
    public readonly ELFCLASS EiClass;
    public readonly ELFDATA EiData;
    public readonly ELFOSABI EiOsAbi;
    public readonly EM EMachine;
    public readonly ET EType;
    public readonly string? Interpreter;

    private ElfFile(
      ELFCLASS eiClass,
      ELFDATA eiData,
      ELFOSABI eiOsAbi,
      byte eiAbiVersion,
      ET eType,
      EM eMachine,
      EF eFlags,
      string? interpreter)
    {
      EiClass = eiClass;
      EiData = eiData;
      EiOsAbi = eiOsAbi;
      EiAbiVersion = eiAbiVersion;
      EType = eType;
      EMachine = eMachine;
      EFlags = eFlags;
      Interpreter = interpreter;
    }

    public static bool Is(Stream stream)
    {
      stream.Position = 0;
      var eIdent = StreamUtil.ReadBytes(stream, EI.EI_NIDENT);
      return
        eIdent[EI.EI_MAG0] == ELFMAG.ELFMAG0 &&
        eIdent[EI.EI_MAG1] == ELFMAG.ELFMAG1 &&
        eIdent[EI.EI_MAG2] == ELFMAG.ELFMAG2 &&
        eIdent[EI.EI_MAG3] == ELFMAG.ELFMAG3 &&
        (EV)eIdent[EI.EI_VERSION] == EV.EV_CURRENT;
    }

    public static ElfFile Parse(Stream stream)
    {
      stream.Position = 0;
      var eIdent = StreamUtil.ReadBytes(stream, EI.EI_NIDENT);

      if (eIdent[EI.EI_MAG0] != ELFMAG.ELFMAG0 ||
          eIdent[EI.EI_MAG1] != ELFMAG.ELFMAG1 ||
          eIdent[EI.EI_MAG2] != ELFMAG.ELFMAG2 ||
          eIdent[EI.EI_MAG3] != ELFMAG.ELFMAG3)
        throw new FormatException("Invalid ELF magic numbers");
      if ((EV)eIdent[EI.EI_VERSION] != EV.EV_CURRENT)
        throw new FormatException("Invalid ELF file version");

      var eiData = (ELFDATA)eIdent[EI.EI_DATA];
      var needSwap = BitConverter.IsLittleEndian != eiData switch
        {
          ELFDATA.ELFDATA2LSB => true,
          ELFDATA.ELFDATA2MSB => false,
          _ => throw new FormatException("Invalid ELF data encoding")
        };

      ushort GetU2(ushort v) => needSwap ? MemoryUtil.SwapU2(v) : v;
      uint GetU4(uint v) => needSwap ? MemoryUtil.SwapU4(v) : v;
      ulong GetU8(ulong v) => needSwap ? MemoryUtil.SwapU8(v) : v;

      unsafe Data Read32()
      {
        Elf32_Ehdr ehdr;
        StreamUtil.ReadBytes(stream, (byte*)&ehdr, sizeof(Elf32_Ehdr));

        if (ehdr.e_ehsize < EI.EI_NIDENT + sizeof(Elf32_Ehdr))
          throw new FormatException("Invalid ELF header size");
        if (GetU4(ehdr.e_version) != 1u)
          throw new FormatException("Invalid ELF object file version");

        stream.Position = GetU4(ehdr.e_phoff);

        var ePhNum = GetU2(ehdr.e_phnum);
        var ePhEntSize = GetU2(ehdr.e_phentsize);
        if (ePhEntSize < sizeof(Elf32_Phdr))
          throw new FormatException("Too small ELF program header entry size");

        string? interpreter = null;
        fixed (byte* buf = StreamUtil.ReadBytes(stream, checked(ePhNum * ePhEntSize)))
        {
          for (var ptr = buf; ePhNum-- > 0; ptr += ePhEntSize)
          {
            Elf32_Phdr phdr;
            MemoryUtil.CopyBytes(ptr, (byte*)&phdr, sizeof(Elf32_Phdr));
            switch ((PT)GetU4(phdr.p_type))
            {
            case PT.PT_INTERP:
              stream.Position = GetU4(phdr.p_offset);
              var interpreterBuf = StreamUtil.ReadBytes(stream, checked((int)GetU4(phdr.p_filesz)));
              interpreter = new string(Encoding.UTF8.GetChars(interpreterBuf, 0, MemoryUtil.GetAsciiStringZSize(interpreterBuf)));
              break;
            }
          }
        }

        return new(
          (ET)GetU2(ehdr.e_type),
          (EM)GetU2(ehdr.e_machine),
          (EF)GetU4(ehdr.e_flags),
          interpreter);
      }

      unsafe Data Read64()
      {
        Elf64_Ehdr ehdr;
        StreamUtil.ReadBytes(stream, (byte*)&ehdr, sizeof(Elf64_Ehdr));

        if (ehdr.e_ehsize < EI.EI_NIDENT + sizeof(Elf64_Ehdr))
          throw new FormatException("Invalid ELF header size");
        if (GetU4(ehdr.e_version) != 1u)
          throw new FormatException("Invalid ELF object file version");

        stream.Position = checked((long)GetU8(ehdr.e_phoff));

        var ePhNum = GetU2(ehdr.e_phnum);
        var ePhEntSize = GetU2(ehdr.e_phentsize);
        if (ePhEntSize < sizeof(Elf64_Phdr))
          throw new FormatException("Too small ELF program header entry size");

        string? interpreter = null;
        fixed (byte* buf = StreamUtil.ReadBytes(stream, checked(ePhNum * ePhEntSize)))
        {
          for (var ptr = buf; ePhNum-- > 0; ptr += ePhEntSize)
          {
            Elf64_Phdr phdr;
            MemoryUtil.CopyBytes(ptr, (byte*)&phdr, sizeof(Elf64_Phdr));
            switch ((PT)GetU4(phdr.p_type))
            {
            case PT.PT_INTERP:
              stream.Position = checked((long)GetU8(phdr.p_offset));
              var interpreterBuf = StreamUtil.ReadBytes(stream, checked((int)GetU8(phdr.p_filesz)));
              interpreter = new string(Encoding.UTF8.GetChars(interpreterBuf, 0, MemoryUtil.GetAsciiStringZSize(interpreterBuf)));
              break;
            }
          }
        }

        return new(
          (ET)GetU2(ehdr.e_type),
          (EM)GetU2(ehdr.e_machine),
          (EF)GetU4(ehdr.e_flags),
          interpreter);
      }

      var eiClass = (ELFCLASS)eIdent[EI.EI_CLASS];
      var data = eiClass switch
        {
          ELFCLASS.ELFCLASS32 => Read32(),
          ELFCLASS.ELFCLASS64 => Read64(),
          _ => throw new FormatException("Invalid ELF file encoding")
        };
      return new(eiClass, eiData, (ELFOSABI)eIdent[EI.EI_OSABI], eIdent[EI.EI_ABIVERSION], data.EType, data.EMachine, data.EFlags, data.Interpreter);
    }

    private readonly struct Data
    {
      public readonly ET EType;
      public readonly EM EMachine;
      public readonly EF EFlags;
      public readonly string? Interpreter;

      public Data(ET eType, EM eMachine, EF eFlags, string? interpreter)
      {
        EType = eType;
        EMachine = eMachine;
        EFlags = eFlags;
        Interpreter = interpreter;
      }
    }
  }
}