using System;
using System.IO;
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
    public readonly Program[] Programs;
    public readonly Section[] Sections;

    private ElfFile(
      ELFCLASS eiClass,
      ELFDATA eiData,
      ELFOSABI eiOsAbi,
      byte eiAbiVersion,
      ET eType,
      EM eMachine,
      EF eFlags,
      Program[] programs,
      Section[] sections)
    {
      EiClass = eiClass;
      EiData = eiData;
      EiOsAbi = eiOsAbi;
      EiAbiVersion = eiAbiVersion;
      EType = eType;
      EMachine = eMachine;
      EFlags = eFlags;
      Programs = programs;
      Sections = sections;
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

    public delegate Stream CreateStreamDelegate();

    public sealed class Program
    {
      public readonly ulong Size;
      public readonly PT Type;
      public readonly PF Flags;
      public readonly CreateStreamDelegate CreateStream;

      internal Program(ulong size, PT type, PF flags, CreateStreamDelegate createStream)
      {
        Size = size;
        Type = type;
        Flags = flags;
        CreateStream = createStream;
      }
    }

    public sealed class Section
    {
      public readonly string Name;
      public readonly ulong Size;
      public readonly ulong Address;
      public readonly ulong AddressAlign;
      public readonly SHT Type;
      public readonly SHF Flags;
      public readonly ushort Link;
      public readonly uint Info;
      public readonly ulong EntSize;
      public readonly CreateStreamDelegate CreateStream;

      internal Section(string name, ulong size, ulong address, ulong addressAlign, SHT type, SHF flags, ushort link, uint info, ulong entSize, CreateStreamDelegate createStream)
      {
        Name = name;
        Size = size;
        Address = address;
        AddressAlign = addressAlign;
        Type = type;
        Flags = flags;
        Link = link;
        Info = info;
        EntSize = entSize;
        CreateStream = createStream;
      }
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

      var needSwap = ElfUtil.NeedSwap(eiData);
      ushort GetU2(ushort v) => needSwap ? EndianUtil.SwapU2(v) : v;
      uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
      ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

      unsafe Hdr Read32()
      {
        Elf32_Ehdr ehdr;
        StreamUtil.ReadBytes(stream, (byte*)&ehdr, sizeof(Elf32_Ehdr));

        if (ehdr.e_ehsize < EI.EI_NIDENT + sizeof(Elf32_Ehdr))
          throw new FormatException("Invalid ELF header size");
        if (GetU4(ehdr.e_version) != 1u)
          throw new FormatException("Invalid ELF object file version");

        Program[] programs;
        {
          var ePhNum = GetU2(ehdr.e_phnum);
          programs = new Program[ePhNum];
          if (ePhNum > 0)
          {
            var ePhEntSize = GetU2(ehdr.e_phentsize);
            if (ePhEntSize < sizeof(Elf32_Phdr))
              throw new FormatException("Too small ELF program header entry size");
            using var phStream = new ReadOnlyNestedStream(stream, GetU4(ehdr.e_phoff), ePhNum * ePhEntSize);
            for (ushort n = 0; n < ePhNum; ++n)
            {
              Elf32_Phdr phdr;
              StreamUtil.ReadBytes(phStream, (byte*)&phdr, sizeof(Elf32_Phdr));
              phStream.Seek(ePhEntSize - sizeof(Elf32_Phdr), SeekOrigin.Current);

              var phOffset = GetU4(phdr.p_offset);
              var phSize = GetU4(phdr.p_filesz);
              programs[n] = new Program(
                phSize, (PT)GetU4(phdr.p_type), (PF)GetU4(phdr.p_flags),
                () => new ReadOnlyNestedStream(stream, phOffset, phSize));
            }
          }
        }

        Section[] sections;
        {
          var eShNum = GetU2(ehdr.e_shnum);
          sections = new Section[eShNum];
          if (eShNum > 0)
          {
            var eShEntSize = GetU2(ehdr.e_shentsize);
            if (eShEntSize < sizeof(Elf32_Shdr))
              throw new FormatException("Too small ELF program header entry size");
            var eShStrNdx = GetU2(ehdr.e_shstrndx);
            if (eShStrNdx >= eShNum)
              throw new FormatException("Too large string index section number");
            using var shStream = new ReadOnlyNestedStream(stream, GetU4(ehdr.e_shoff), eShNum * eShEntSize);

            shStream.Position = eShStrNdx * eShEntSize;
            Elf32_Shdr strShdr;
            StreamUtil.ReadBytes(shStream, (byte*)&strShdr, sizeof(Elf32_Shdr));
            using var stringStream = new ReadOnlyNestedStream(stream, GetU4(strShdr.sh_offset), GetU4(strShdr.sh_size));

            shStream.Position = 0;
            for (ushort n = 0; n < eShNum; ++n)
            {
              Elf32_Shdr shdr;
              StreamUtil.ReadBytes(shStream, (byte*)&shdr, sizeof(Elf32_Shdr));
              shStream.Seek(eShEntSize - sizeof(Elf32_Shdr), SeekOrigin.Current);

              stringStream.Position = GetU4(shdr.sh_name);
              var shName = ElfUtil.ReadStringZ(stringStream);

              var shType = (SHT)GetU4(shdr.sh_type);
              var shOffset = GetU4(shdr.sh_offset);
              var shAddr = GetU4(shdr.sh_addr);
              var shAddrAlign = GetU4(shdr.sh_addralign);
              var shSize = GetU4(shdr.sh_size);
              sections[n] = new Section(
                shName, shSize, shAddr, shAddrAlign, shType, (SHF)GetU4(shdr.sh_flags), checked((ushort)GetU4(shdr.sh_link)), GetU4(shdr.sh_info), GetU4(shdr.sh_entsize),
                () => shType == SHT.SHT_NOBITS ? throw new InvalidOperationException("Section has no data") : new ReadOnlyNestedStream(stream, shOffset, shSize));
            }
          }
        }

        return new(
          (ET)GetU2(ehdr.e_type),
          (EM)GetU2(ehdr.e_machine),
          (EF)GetU4(ehdr.e_flags),
          programs,
          sections);
      }

      unsafe Hdr Read64()
      {
        Elf64_Ehdr ehdr;
        StreamUtil.ReadBytes(stream, (byte*)&ehdr, sizeof(Elf64_Ehdr));

        if (ehdr.e_ehsize < EI.EI_NIDENT + sizeof(Elf64_Ehdr))
          throw new FormatException("Invalid ELF header size");
        if (GetU4(ehdr.e_version) != 1u)
          throw new FormatException("Invalid ELF object file version");

        Program[] programs;
        {
          var ePhNum = GetU2(ehdr.e_phnum);
          programs = new Program[ePhNum];
          if (ePhNum > 0)
          {
            var ePhEntSize = GetU2(ehdr.e_phentsize);
            if (ePhEntSize < sizeof(Elf64_Phdr))
              throw new FormatException("Too small ELF program header entry size");
            using var phStream = new ReadOnlyNestedStream(stream, checked((long)GetU8(ehdr.e_phoff)), ePhNum * ePhEntSize);
            for (ushort n = 0; n < ePhNum; ++n)
            {
              Elf64_Phdr phdr;
              StreamUtil.ReadBytes(phStream, (byte*)&phdr, sizeof(Elf64_Phdr));
              phStream.Seek(ePhEntSize - sizeof(Elf64_Phdr), SeekOrigin.Current);

              var phOffset = GetU8(phdr.p_offset);
              var phSize = GetU8(phdr.p_filesz);
              programs[n] = new Program(
                phSize, (PT)GetU4(phdr.p_type), (PF)GetU4(phdr.p_flags),
                () => new ReadOnlyNestedStream(stream, checked((long)phOffset), checked((long)phSize)));
            }
          }
        }

        Section[] sections;
        {
          var eShNum = GetU2(ehdr.e_shnum);
          sections = new Section[eShNum];
          if (eShNum > 0)
          {
            var eShEntSize = GetU2(ehdr.e_shentsize);
            if (eShEntSize < sizeof(Elf64_Shdr))
              throw new FormatException("Too small ELF program header entry size");
            var eShStrNdx = GetU2(ehdr.e_shstrndx);
            if (eShStrNdx >= eShNum)
              throw new FormatException("Too large string index section number");
            using var shStream = new ReadOnlyNestedStream(stream, checked((long)GetU8(ehdr.e_shoff)), eShNum * eShEntSize);

            shStream.Position = eShStrNdx * eShEntSize;
            Elf64_Shdr strShdr;
            StreamUtil.ReadBytes(shStream, (byte*)&strShdr, sizeof(Elf64_Shdr));
            using var stringStream = new ReadOnlyNestedStream(stream, checked((long)GetU8(strShdr.sh_offset)), checked((long)GetU8(strShdr.sh_size)));

            shStream.Position = 0;
            for (ushort n = 0; n < eShNum; ++n)
            {
              Elf64_Shdr shdr;
              StreamUtil.ReadBytes(shStream, (byte*)&shdr, sizeof(Elf64_Shdr));
              shStream.Seek(eShEntSize - sizeof(Elf64_Shdr), SeekOrigin.Current);

              stringStream.Position = GetU4(shdr.sh_name);
              var shName = ElfUtil.ReadStringZ(stringStream);

              var shType = (SHT)GetU4(shdr.sh_type);
              var shOffset = GetU8(shdr.sh_offset);
              var shAddr = GetU8(shdr.sh_addr);
              var shAddrAlign = GetU8(shdr.sh_addralign);
              var shSize = GetU8(shdr.sh_size);
              sections[n] = new Section(
                shName, shSize, shAddr, shAddrAlign, shType, (SHF)checked((uint)GetU8(shdr.sh_flags)), checked((ushort)GetU4(shdr.sh_link)), GetU4(shdr.sh_info), GetU8(shdr.sh_entsize),
                () => shType == SHT.SHT_NOBITS ? throw new InvalidOperationException("Section has no data") : new ReadOnlyNestedStream(stream, checked((long)shOffset), checked((long)shSize)));
            }
          }
        }

        return new(
          (ET)GetU2(ehdr.e_type),
          (EM)GetU2(ehdr.e_machine),
          (EF)GetU4(ehdr.e_flags),
          programs,
          sections);
      }

      var eiClass = (ELFCLASS)eIdent[EI.EI_CLASS];
      var hdr = eiClass switch
        {
          ELFCLASS.ELFCLASS32 => Read32(),
          ELFCLASS.ELFCLASS64 => Read64(),
          _ => throw new FormatException("Invalid ELF file encoding")
        };
      return new(eiClass, eiData, (ELFOSABI)eIdent[EI.EI_OSABI], eIdent[EI.EI_ABIVERSION], hdr.EType, hdr.EMachine, hdr.EFlags, hdr.Programs, hdr.Sections);
    }

    private sealed class Hdr
    {
      public readonly ET EType;
      public readonly EM EMachine;
      public readonly EF EFlags;
      public readonly Program[] Programs;
      public readonly Section[] Sections;

      public Hdr(ET eType, EM eMachine, EF eFlags, Program[] programs, Section[] sections)
      {
        EType = eType;
        EMachine = eMachine;
        EFlags = eFlags;
        Programs = programs;
        Sections = sections;
      }
    }
  }
}