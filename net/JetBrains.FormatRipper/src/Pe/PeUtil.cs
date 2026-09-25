using System;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.Pe.Impl;

namespace JetBrains.FormatRipper.Pe
{
  public static class PeUtil
  {
    public static string ReadStringZ(Stream stream) => StreamUtil.ReadStringZ(stream);

    public sealed class Export
    {
      public readonly string? Name;
      public readonly uint Ordinal;
      public readonly uint VirtualAddress;
      public readonly string? Forwarder;
      public readonly PeFile.CreateStreamDelegate? CreateStream;

      internal Export(string? name, uint ordinal, uint virtualAddress, string? forwarder, PeFile.CreateStreamDelegate? createStream)
      {
        Name = name;
        Ordinal = ordinal;
        VirtualAddress = virtualAddress;
        Forwarder = forwarder;
        CreateStream = createStream;
      }
    }

    public delegate bool ExportFilterDelegate(Export export);

    /// <summary>
    /// Reads the export directory of the PE image. The named exports go first in the order of the export name table,
    /// then the exports by ordinal only. The forwarded exports have no data, see <see cref="Export.Forwarder"/>. The
    /// parsed stream should stay opened while the <see cref="Export.CreateStream"/> delegates are in use.
    /// </summary>
    public static unsafe bool GetExports(PeFile file, ExportFilterDelegate exportFilter)
    {
      var exportDirectory = file.ExportDirectory;
      if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size == 0)
        return true;

      var sections = file.Sections;

      IMAGE_EXPORT_DIRECTORY ied;
      using (var iedStream = OpenStream(sections, exportDirectory.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY)))
        StreamUtil.ReadBytes(iedStream, (byte*)&ied, sizeof(IMAGE_EXPORT_DIRECTORY));

      var ordinalBase = EndianUtil.GetLeU4(ied.Base);
      var numberOfNames = EndianUtil.GetLeU4(ied.NumberOfNames);
      var functions = ReadU4Array(sections, EndianUtil.GetLeU4(ied.AddressOfFunctions), EndianUtil.GetLeU4(ied.NumberOfFunctions));
      var names = ReadU4Array(sections, EndianUtil.GetLeU4(ied.AddressOfNames), numberOfNames);
      var nameOrdinals = ReadU2Array(sections, EndianUtil.GetLeU4(ied.AddressOfNameOrdinals), numberOfNames);

      var hasNames = new bool[functions.Length];
      for (var n = 0; n < names.Length; ++n)
      {
        var index = nameOrdinals[n];
        if (index >= functions.Length)
          throw new FormatException("Invalid PE export name ordinal");
        hasNames[index] = true;
        if (!exportFilter(MakeExport(sections, exportDirectory, ReadString(sections, names[n]), ordinalBase + index, functions[index])))
          return false;
      }

      for (var index = 0u; index < functions.Length; ++index)
        if (!hasNames[index] && functions[index] != 0)
          if (!exportFilter(MakeExport(sections, exportDirectory, null, ordinalBase + index, functions[index])))
            return false;

      return true;

      static Export MakeExport(PeFile.Section[] sections, PeFile.DataDirectory exportDirectory, string? name, uint ordinal, uint virtualAddress)
      {
        // Note: the forwarded export points to the forwarder string inside the export directory instead of the exported data
        if (exportDirectory.VirtualAddress <= virtualAddress && virtualAddress - exportDirectory.VirtualAddress < exportDirectory.Size)
          return new Export(name, ordinal, virtualAddress, ReadString(sections, virtualAddress), null);
        return new Export(name, ordinal, virtualAddress, null, MakeCreateStream(sections, virtualAddress));
      }

      static string ReadString(PeFile.Section[] sections, uint virtualAddress)
      {
        using var stream = OpenStream(sections, virtualAddress, 0);
        return ReadStringZ(stream);
      }

      static uint[] ReadU4Array(PeFile.Section[] sections, uint virtualAddress, uint count)
      {
        if (count == 0)
          return new uint[0];
        using var stream = OpenStream(sections, virtualAddress, checked(count * sizeof(uint)));
        var array = new uint[count];
        fixed (uint* ptr = array)
          StreamUtil.ReadBytes(stream, (byte*)ptr, checked((int)count * sizeof(uint)));
        for (var n = 0; n < array.Length; ++n)
          array[n] = EndianUtil.GetLeU4(array[n]);
        return array;
      }

      static ushort[] ReadU2Array(PeFile.Section[] sections, uint virtualAddress, uint count)
      {
        if (count == 0)
          return new ushort[0];
        using var stream = OpenStream(sections, virtualAddress, checked(count * sizeof(ushort)));
        var array = new ushort[count];
        fixed (ushort* ptr = array)
          StreamUtil.ReadBytes(stream, (byte*)ptr, checked((int)count * sizeof(ushort)));
        for (var n = 0; n < array.Length; ++n)
          array[n] = EndianUtil.GetLeU2(array[n]);
        return array;
      }

      static Stream OpenStream(PeFile.Section[] sections, uint virtualAddress, long minSize)
      {
        var createStream = MakeCreateStream(sections, virtualAddress) ?? throw new FormatException("Invalid PE export directory address");
        var stream = createStream();
        if (stream.Length < minSize)
        {
          stream.Dispose();
          throw new FormatException("Invalid PE export directory size");
        }

        return stream;
      }

      static PeFile.CreateStreamDelegate? MakeCreateStream(PeFile.Section[] sections, uint virtualAddress)
      {
        foreach (var section in sections)
          if (section.VirtualAddress <= virtualAddress && virtualAddress - section.VirtualAddress < Math.Max(section.VirtualSize, section.SizeOfRawData))
            return MakeSectionCreateStream(section, virtualAddress - section.VirtualAddress);
        return null;
      }
    }

    public sealed class Symbol
    {
      public readonly string Name;
      public readonly uint Value;
      public readonly ushort SectionNumber;
      public readonly IMAGE_SYM_TYPE BaseType;
      public readonly IMAGE_SYM_DTYPE DerivedType;
      public readonly IMAGE_SYM_CLASS StorageClass;
      public readonly byte NumberOfAuxSymbols;
      public readonly PeFile.CreateStreamDelegate? CreateStream;

      internal Symbol(string name, uint value, ushort sectionNumber, IMAGE_SYM_TYPE baseType, IMAGE_SYM_DTYPE derivedType, IMAGE_SYM_CLASS storageClass, byte numberOfAuxSymbols, PeFile.CreateStreamDelegate? createStream)
      {
        Name = name;
        Value = value;
        SectionNumber = sectionNumber;
        BaseType = baseType;
        DerivedType = derivedType;
        StorageClass = storageClass;
        NumberOfAuxSymbols = numberOfAuxSymbols;
        CreateStream = createStream;
      }
    }

    public delegate bool SymbolFilterDelegate(Symbol symbol);

    /// <summary>
    /// Reads the COFF symbol table of the PE image. The auxiliary symbol records are skipped, see
    /// <see cref="Symbol.NumberOfAuxSymbols"/>. The <see cref="Symbol.DerivedType"/> holds all the type bits above the
    /// <see cref="Symbol.BaseType"/> ones. The parsed stream should stay opened while the <see cref="Symbol.CreateStream"/>
    /// delegates are in use.
    /// </summary>
    public static unsafe bool GetSymbols(PeFile file, SymbolFilterDelegate symbolFilter)
    {
      var pointerToSymbolTable = file.PointerToSymbolTable;
      var numberOfSymbols = file.NumberOfSymbols;
      if (pointerToSymbolTable == 0 || numberOfSymbols == 0)
        return true;

      using var fileStream = file.CreateStream();

      var symSize = checked((long)numberOfSymbols * sizeof(IMAGE_SYMBOL));
      var strOffset = checked(pointerToSymbolTable + symSize);
      if (strOffset > fileStream.Length - sizeof(uint))
        throw new FormatException("Invalid PE symbol table size");

      // Note: the string table follows the symbol table and starts with its size including the size field, some tools write zero for the empty one
      uint rawStrSize;
      fileStream.Position = strOffset;
      StreamUtil.ReadBytes(fileStream, (byte*)&rawStrSize, sizeof(uint));
      var strSize = Math.Max(EndianUtil.GetLeU4(rawStrSize), (uint)sizeof(uint));
      if (strSize > fileStream.Length - strOffset)
        throw new FormatException("Invalid PE string table size");

      using var symStream = new ReadOnlyNestedStream(fileStream, pointerToSymbolTable, symSize);
      using var strStream = new ReadOnlyNestedStream(fileStream, strOffset, strSize);

      var sections = file.Sections;
      for (var n = 0u; n < numberOfSymbols; ++n)
      {
        IMAGE_SYMBOL isym;
        StreamUtil.ReadBytes(symStream, (byte*)&isym, sizeof(IMAGE_SYMBOL));

        var numberOfAuxSymbols = isym.NumberOfAuxSymbols;
        if (numberOfAuxSymbols >= numberOfSymbols - n)
          throw new FormatException("Invalid PE auxiliary symbol count");
        symStream.Seek(numberOfAuxSymbols * sizeof(IMAGE_SYMBOL), SeekOrigin.Current);
        n += numberOfAuxSymbols;

        string name;
        if (isym.Short == 0)
        {
          var nameOffset = EndianUtil.GetLeU4(isym.Long);
          if (nameOffset >= strSize)
            throw new FormatException("Invalid PE symbol name offset");
          strStream.Position = nameOffset;
          name = ReadStringZ(strStream);
        }
        else
          name = GetName((byte*)&isym, ImageSection.IMAGE_SIZEOF_SHORT_NAME);

        var value = EndianUtil.GetLeU4(isym.Value);
        var sectionNumber = EndianUtil.GetLeU2(isym.SectionNumber);
        var type = EndianUtil.GetLeU2(isym.Type);
        var storageClass = (IMAGE_SYM_CLASS)isym.StorageClass;

        // Note: the value is the offset in the section only for these storage classes
        PeFile.CreateStreamDelegate? createStream = null;
        if (IMAGE_SYM.IMAGE_SYM_UNDEFINED < (IMAGE_SYM)sectionNumber && (IMAGE_SYM)sectionNumber <= IMAGE_SYM.IMAGE_SYM_SECTION_MAX &&
            storageClass is IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_EXTERNAL or IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_STATIC or IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_LABEL)
        {
          if (sectionNumber > sections.Length)
            throw new FormatException("Invalid PE symbol section number");
          var section = sections[sectionNumber - 1];
          if (value > Math.Max(section.VirtualSize, section.SizeOfRawData))
            throw new FormatException("Invalid PE symbol section offset");
          createStream = MakeSectionCreateStream(section, value);
        }

        if (!symbolFilter(new Symbol(
              name,
              value,
              sectionNumber,
              (IMAGE_SYM_TYPE)(type & ImageSymbol.N_BTMASK),
              (IMAGE_SYM_DTYPE)(type >> ImageSymbol.N_BTSHFT),
              storageClass,
              numberOfAuxSymbols,
              createStream)))
          return false;
      }

      return true;

      static string GetName(byte* buf, int nameSize)
      {
        var blob = MemoryUtil.CopyBytes(buf, nameSize);
        return new string(Encoding.UTF8.GetChars(blob, 0, MemoryUtil.GetAsciiStringZSize(blob)));
      }
    }

    private static PeFile.CreateStreamDelegate? MakeSectionCreateStream(PeFile.Section section, uint offset)
    {
      // Note: the section tail beyond the raw data is zero-filled by the loader, so there is no file data for it
      var createSectionStream = section.CreateStream;
      if (createSectionStream == null || offset >= section.SizeOfRawData)
        return null;
      var size = section.SizeOfRawData - offset;
      return () => new ReadOnlyNestedStream(createSectionStream(), offset, size);
    }
  }
}
