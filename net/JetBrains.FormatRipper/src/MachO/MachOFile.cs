using System;
using System.IO;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.MachO
{
  public sealed class MachOFile
  {
    public delegate Stream CreateStreamDelegate();

    public sealed class Command
    {
      public readonly LC Type;
      public readonly uint Size;
      public readonly CreateStreamDelegate CreateStream;

      internal Command(LC type, uint size, CreateStreamDelegate createStream)
      {
        Type = type;
        Size = size;
        CreateStream = createStream;
      }
    }

    public sealed class Section
    {
      public readonly Endian Endian;
      public readonly CPU_TYPE CpuType;
      public readonly CPU_SUBTYPE CpuSubType;
      public readonly MH_FileType MhFileType;
      public readonly MH_Flags MhFlags;
      public readonly Command[] Commands;
      public readonly CreateStreamDelegate CreateStream;
      public readonly long ImageOffset;
      public readonly uint SizeOfLoadCommands;

      internal Section(
        BaseSection baseSection,
        CreateStreamDelegate createStream,
        long imageOffset)
      {
        Endian = baseSection.Endian;
        CpuType = baseSection.CpuType;
        CpuSubType = baseSection.CpuSubType;
        MhFileType = baseSection.MhFileType;
        MhFlags = baseSection.MhFlags;
        Commands = baseSection.Commands;
        CreateStream = createStream;
        ImageOffset = imageOffset;
        SizeOfLoadCommands = baseSection.SizeOfCmds;
      }
    }

    public readonly Endian? FatEndian;
    public readonly Section[] Sections;

    public enum Endian
    {
      Big,
      Little
    }

    [Flags]
    public enum Mode : uint
    {
      Default = 0x0,
      SignatureData = 0x1
    }

    public enum SignatureType
    {
      None,
      AdHoc,
      Regular,
    }

    private MachOFile(Section section) : this(null, new[] { section })
    {
    }

    private MachOFile(Endian? fatEndian, Section[] sections)
    {
      FatEndian = fatEndian;
      Sections = sections;
    }

    public static unsafe bool Is(Stream stream)
    {
      stream.Position = 0;
      return ReadMagic(stream) switch
        {
          MH.FAT_MAGIC => ReadFat32(Endian.Little, stream),
          MH.FAT_CIGAM => ReadFat32(Endian.Big, stream),
          MH.FAT_MAGIC_64 => ReadFat64(Endian.Little, stream),
          MH.FAT_CIGAM_64 => ReadFat64(Endian.Big, stream),
          MH.MH_MAGIC or MH.MH_CIGAM or MH.MH_MAGIC_64 or MH.MH_CIGAM_64 => true,
          _ => false,
        };

      static bool ReadFat32(Endian fatEndian, Stream stream)
      {
        var needSwap = MachOUtil.NeedSwap(fatEndian);
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;

        fat_header fh;
        StreamUtil.ReadBytes(stream, (byte*)&fh, sizeof(fat_header));
        var nFatArch = GetU4(fh.nfat_arch);

        var fas = new fat_arch[nFatArch];
        fixed (fat_arch* ptr = fas)
          StreamUtil.ReadBytes(stream, (byte*)ptr, checked((int)nFatArch * sizeof(fat_arch)));
        for (var n = 0u; n < nFatArch; ++n)
        {
          stream.Position = GetU4(fas[n].offset);
          if (ReadMagic(stream) is not (MH.MH_MAGIC or MH.MH_MAGIC_64 or MH.MH_CIGAM or MH.MH_CIGAM_64))
            return false;
        }

        return true;
      }

      static bool ReadFat64(Endian fatEndian, Stream stream)
      {
        var needSwap = MachOUtil.NeedSwap(fatEndian);
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
        ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

        fat_header fh;
        StreamUtil.ReadBytes(stream, (byte*)&fh, sizeof(fat_header));
        var nFatArch = GetU4(fh.nfat_arch);

        var fas = new fat_arch_64[nFatArch];
        fixed (fat_arch_64* ptr = fas)
          StreamUtil.ReadBytes(stream, (byte*)ptr, checked((int)nFatArch * sizeof(fat_arch_64)));
        for (var n = 0u; n < nFatArch; ++n)
        {
          stream.Position = checked((long)GetU8(fas[n].offset));
          if (ReadMagic(stream) is not (MH.MH_MAGIC or MH.MH_CIGAM or MH.MH_MAGIC_64 or MH.MH_CIGAM_64))
            return false;
        }

        return true;
      }
    }

    public static unsafe MachOFile Parse(Stream stream)
    {
      stream.Position = 0;
      ReadOnlyNestedStream CreateSectionStream() => new(stream, 0, stream.Length);
      return ReadMagic(stream) switch
        {
          MH.FAT_MAGIC => ReadFat32(Endian.Little, stream),
          MH.FAT_CIGAM => ReadFat32(Endian.Big, stream),
          MH.FAT_MAGIC_64 => ReadFat64(Endian.Little, stream),
          MH.FAT_CIGAM_64 => ReadFat64(Endian.Big, stream),
          MH.MH_MAGIC => new(new Section(Read32(Endian.Little, stream), CreateSectionStream, 0)),
          MH.MH_CIGAM => new(new Section(Read32(Endian.Big, stream), CreateSectionStream, 0)),
          MH.MH_MAGIC_64 => new(new Section(Read64(Endian.Little, stream), CreateSectionStream, 0)),
          MH.MH_CIGAM_64 => new(new Section(Read64(Endian.Big, stream), CreateSectionStream, 0)),
          _ => throw new FormatException("Unknown Mach-O magic numbers")
        };

      static MachOFile ReadFat32(Endian fatEndian, Stream stream)
      {
        var needSwap = MachOUtil.NeedSwap(fatEndian);
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;

        fat_header fh;
        StreamUtil.ReadBytes(stream, (byte*)&fh, sizeof(fat_header));
        var nFatArch = GetU4(fh.nfat_arch);

        var sections = new Section[nFatArch];
        using (var fasStream = new ReadOnlyNestedStream(stream, stream.Position, nFatArch * sizeof(fat_arch)))
          for (var n = 0u; n < nFatArch; ++n)
          {
            fat_arch fa;
            StreamUtil.ReadBytes(fasStream, (byte*)&fa, sizeof(fat_arch));
            var cpuType = (CPU_TYPE)GetU4(fa.cputype);
            var cpuSubType = (CPU_SUBTYPE)GetU4(fa.cpusubtype);
            var offset = GetU4(fa.offset);
            var size = GetU4(fa.size);

            Section section;
            ReadOnlyNestedStream CreateSectionStream() => new(stream, offset, size);
            using (var sectionStream = CreateSectionStream())
              section = new Section(ReadMagic(sectionStream) switch
                {
                  MH.MH_MAGIC => Read32(Endian.Little, sectionStream),
                  MH.MH_CIGAM => Read32(Endian.Big, sectionStream),
                  MH.MH_MAGIC_64 => Read64(Endian.Little, sectionStream),
                  MH.MH_CIGAM_64 => Read64(Endian.Big, sectionStream),
                  _ => throw new FormatException("Unknown Mach-O magic numbers")
                }, CreateSectionStream, offset);
            if (section.CpuType != cpuType)
              throw new FormatException("Inconsistent cpu type in fat header");
            if (section.CpuSubType != cpuSubType)
              throw new FormatException("Inconsistent cpu subtype in fat header");
            sections[n] = section;
          }

        return new(fatEndian, sections);
      }

      static MachOFile ReadFat64(Endian fatEndian, Stream stream)
      {
        var needSwap = MachOUtil.NeedSwap(fatEndian);
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
        ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

        fat_header fh;
        StreamUtil.ReadBytes(stream, (byte*)&fh, sizeof(fat_header));
        var nFatArch = GetU4(fh.nfat_arch);

        var sections = new Section[nFatArch];
        using (var fasStream = new ReadOnlyNestedStream(stream, stream.Position, nFatArch * sizeof(fat_arch_64)))
          for (var n = 0u; n < nFatArch; ++n)
          {
            fat_arch_64 fa;
            StreamUtil.ReadBytes(fasStream, (byte*)&fa, sizeof(fat_arch_64));
            var cpuType = (CPU_TYPE)GetU4(fa.cputype);
            var cpuSubType = (CPU_SUBTYPE)GetU4(fa.cpusubtype);
            var offset = GetU8(fa.offset);
            var size = GetU8(fa.size);

            Section section;
            ReadOnlyNestedStream CreateSectionStream() => new(stream, checked((long)offset), checked((long)size));
            using (var sectionStream = CreateSectionStream())
              section = new Section(ReadMagic(sectionStream) switch
                {
                  MH.MH_MAGIC => Read32(Endian.Little, sectionStream),
                  MH.MH_CIGAM => Read32(Endian.Big, sectionStream),
                  MH.MH_MAGIC_64 => Read64(Endian.Little, sectionStream),
                  MH.MH_CIGAM_64 => Read64(Endian.Big, sectionStream),
                  _ => throw new FormatException("Unknown Mach-O magic numbers")
                }, CreateSectionStream, checked((long)offset));
            if (section.CpuType != cpuType)
              throw new FormatException("Inconsistent cpu type in fat header");
            if (section.CpuSubType != cpuSubType)
              throw new FormatException("Inconsistent cpu subtype in fat header");
            sections[n] = section;
          }

        return new(fatEndian, sections);
      }

      static BaseSection Read32(Endian endian, Stream sectionStream)
      {
        var needSwap = MachOUtil.NeedSwap(endian);
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;

        mach_header mh;
        StreamUtil.ReadBytes(sectionStream, (byte*)&mh, sizeof(mach_header));
        var nCmds = GetU4(mh.ncmds);
        var sizeOfCmds = GetU4(mh.sizeofcmds);

        var offset = sectionStream.Position;

        Command[] commands;
        using (var commandsStream = new ReadOnlyNestedStream(sectionStream, offset, sizeOfCmds))
          commands = ReadCommands(endian, nCmds, commandsStream);

        return new BaseSection(
          endian,
          (CPU_TYPE)GetU4(mh.cputype),
          (CPU_SUBTYPE)GetU4(mh.cpusubtype),
          (MH_FileType)GetU4(mh.filetype),
          (MH_Flags)GetU4(mh.flags),
          commands,
          sizeOfCmds);
      }

      static BaseSection Read64(Endian endian, Stream sectionStream)
      {
        var needSwap = MachOUtil.NeedSwap(endian);
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;

        mach_header_64 mh;
        StreamUtil.ReadBytes(sectionStream, (byte*)&mh, sizeof(mach_header_64));
        var nCmds = GetU4(mh.ncmds);
        var sizeOfCmds = GetU4(mh.sizeofcmds);

        var offset = sectionStream.Position;

        Command[] commands;
        using (var commandsStream = new ReadOnlyNestedStream(sectionStream, offset, sizeOfCmds))
          commands = ReadCommands(endian, nCmds, commandsStream);

        return new BaseSection(
          endian,
          (CPU_TYPE)GetU4(mh.cputype),
          (CPU_SUBTYPE)GetU4(mh.cpusubtype),
          (MH_FileType)GetU4(mh.filetype),
          (MH_Flags)GetU4(mh.flags),
          commands,
          sizeOfCmds);
      }

      static Command[] ReadCommands(Endian endian, uint nCmds, Stream commandStream)
      {
        var needSwap = MachOUtil.NeedSwap(endian);
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;

        var commands = new Command[checked((int)nCmds)];
        for (var n = 0; n < commands.Length; ++n)
        {
          var offset = commandStream.Position;

          load_command lc;
          StreamUtil.ReadBytes(commandStream, (byte*)&lc, sizeof(load_command));
          var cmd = (LC)GetU4(lc.cmd);
          var cmdSize = GetU4(lc.cmdsize);
          if (cmdSize < sizeof(load_command))
            throw new FormatException($"Invalid {nameof(load_command)} size");

          commandStream.Position = offset;
          var commandBytes = StreamUtil.ReadBytes(commandStream, checked((int)cmdSize));
          commands[n] = new Command(cmd, cmdSize, () => new MemoryStream(commandBytes, false));
        }

        return commands;
      }
    }

    private static unsafe MH ReadMagic(Stream stream)
    {
      uint rawMagic;
      StreamUtil.ReadBytes(stream, (byte*)&rawMagic, sizeof(uint));
      return (MH)EndianUtil.GetLeU4(rawMagic);
    }

    internal sealed class BaseSection
    {
      public readonly Endian Endian;
      public readonly CPU_TYPE CpuType;
      public readonly CPU_SUBTYPE CpuSubType;
      public readonly MH_FileType MhFileType;
      public readonly MH_Flags MhFlags;
      public readonly Command[] Commands;
      public readonly uint SizeOfCmds;

      internal BaseSection(Endian endian,
        CPU_TYPE cpuType,
        CPU_SUBTYPE cpuSubType,
        MH_FileType mhFileType,
        MH_Flags mhFlags,
        Command[] commands,
        uint sizeOfCmds)
      {
        Endian = endian;
        CpuType = cpuType;
        CpuSubType = cpuSubType;
        MhFileType = mhFileType;
        MhFlags = mhFlags;
        Commands = commands;
        SizeOfCmds = sizeOfCmds;
      }
    }
  }
}