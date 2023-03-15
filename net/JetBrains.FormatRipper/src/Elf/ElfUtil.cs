using System;
using System.IO;
using System.Text;
using JetBrains.SignatureVerifier.Elf.Impl;

namespace JetBrains.SignatureVerifier.Elf
{
  public static class ElfUtil
  {
    public static unsafe ElfInfo GetElfInfo(Stream stream)
    {
      byte[] ReadBytes(int size)
      {
        var buf = new byte[size];
        for (var n = 0; n < size;)
        {
          var read = stream.Read(buf, n, size - n);
          if (read == 0)
            throw new EndOfStreamException();
          n += read;
        }

        return buf;
      }

      try
      {
        var pos = stream.Position;
        var eIdent = ReadBytes(ElfDeclaration.EI_NIDENT);

        var eiClass = (ElfClass)eIdent[ElfDeclaration.EI_CLASS];
        var eiData = (ElfData)eIdent[ElfDeclaration.EI_DATA];

        if (eIdent[ElfDeclaration.EI_MAG0] != ElfDeclaration.ELFMAG0 ||
            eIdent[ElfDeclaration.EI_MAG1] != ElfDeclaration.ELFMAG1 ||
            eIdent[ElfDeclaration.EI_MAG2] != ElfDeclaration.ELFMAG2 ||
            eIdent[ElfDeclaration.EI_MAG3] != ElfDeclaration.ELFMAG3)
          throw new FormatException("Invalid ELF magic numbers");
        if ((ElfVersion)eIdent[ElfDeclaration.EI_VERSION] != ElfVersion.EV_CURRENT)
          throw new FormatException("Invalid ELF file version");

        var needSwap = BitConverter.IsLittleEndian != eiData switch
          {
            ElfData.ELFDATA2LSB => true,
            ElfData.ELFDATA2MSB => false,
            _ => throw new FormatException("Invalid ELF data encoding")
          };

        ushort SwapU2(ushort v) => needSwap ? (ushort)((v << 8) | (v >> 8)) : v;
        uint SwapU4(uint v) => needSwap ? ((uint)SwapU2((ushort)v) << 16) | SwapU2((ushort)(v >> 16)) : v;
        ulong SwapU8(ulong v) => needSwap ? ((ulong)SwapU4((uint)v) << 32) | SwapU4((uint)(v >> 32)) : v;

        switch (eiClass)
        {
        case ElfClass.ELFCLASS32:
          {
            Elf32_Ehdr ehdr;
            fixed (byte* buf = ReadBytes(sizeof(Elf32_Ehdr)))
              ehdr = *(Elf32_Ehdr*)buf;

            if (SwapU4(ehdr.e_version) != 1u)
              throw new FormatException("Invalid ELF object file version");

            stream.Seek(pos + SwapU4(ehdr.e_phoff), SeekOrigin.Begin);

            string interpreter = null;
            var ePhEntSize = SwapU2(ehdr.e_phentsize);
            for (var n = SwapU2(ehdr.e_phnum); n-- > 0;)
            {
              Elf32_Phdr phdr;
              fixed (byte* buf = ReadBytes(Math.Max(sizeof(Elf32_Phdr), ePhEntSize)))
                phdr = *(Elf32_Phdr*)buf;

              if ((ElfSegmentType)SwapU4(phdr.p_type) == ElfSegmentType.PT_INTERP)
              {
                stream.Seek(pos + SwapU4(phdr.p_offset), SeekOrigin.Begin);
                interpreter = new string(Encoding.UTF8.GetChars(ReadBytes(checked((int)SwapU4(phdr.p_filesz) - 1))));
                break;
              }
            }

            return new ElfInfo(eiClass, eiData,
              (ElfOsAbi)eIdent[ElfDeclaration.EI_OSABI],
              eIdent[ElfDeclaration.EI_ABIVERSION],
              (ElfType)SwapU2(ehdr.e_type),
              (ElfMachine)SwapU2(ehdr.e_machine),
              (ElfFlags)SwapU4(ehdr.e_flags),
              interpreter);
          }
        case ElfClass.ELFCLASS64:
          {
            Elf64_Ehdr ehdr;
            fixed (byte* buf = ReadBytes(sizeof(Elf64_Ehdr)))
              ehdr = *(Elf64_Ehdr*)buf;

            if (SwapU4(ehdr.e_version) != 1u)
              throw new FormatException("Invalid ELF object file version");

            stream.Seek(checked(pos + (long)SwapU8(ehdr.e_phoff)), SeekOrigin.Begin);

            string interpreter = null;
            var ePhEntSize = SwapU2(ehdr.e_phentsize);
            for (var n = SwapU2(ehdr.e_phnum); n-- > 0;)
            {
              Elf64_Phdr phdr;
              fixed (byte* buf = ReadBytes(Math.Max(sizeof(Elf64_Phdr), ePhEntSize)))
                phdr = *(Elf64_Phdr*)buf;

              if ((ElfSegmentType)SwapU4(phdr.p_type) == ElfSegmentType.PT_INTERP)
              {
                stream.Seek(checked(pos + (long)SwapU8(phdr.p_offset)), SeekOrigin.Begin);
                interpreter = new string(Encoding.UTF8.GetChars(ReadBytes(checked((int)(SwapU8(phdr.p_filesz) - 1)))));
                break;
              }
            }

            return new ElfInfo(eiClass, eiData,
              (ElfOsAbi)eIdent[ElfDeclaration.EI_OSABI],
              eIdent[ElfDeclaration.EI_ABIVERSION],
              (ElfType)SwapU2(ehdr.e_type),
              (ElfMachine)SwapU2(ehdr.e_machine),
              (ElfFlags)SwapU4(ehdr.e_flags),
              interpreter);
          }
        default:
          throw new FormatException("Invalid ELF file encoding");
        }
      }
      catch (IOException)
      {
        throw new InvalidDataException("Unknown format");
      }
    }
  }
}