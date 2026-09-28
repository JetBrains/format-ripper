using System;
using System.Diagnostics.CodeAnalysis;
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
    public static bool GetExports(PeFile file, ExportFilterDelegate exportFilter)
    {
      var exportDirectory = file.ExportDirectory;
      if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size == 0)
        return true;

      var sections = file.Sections;
      var ied = ReadExportDirectory(sections, exportDirectory);

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

      static unsafe uint[] ReadU4Array(PeFile.Section[] sections, uint virtualAddress, uint count)
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

      static unsafe ushort[] ReadU2Array(PeFile.Section[] sections, uint virtualAddress, uint count)
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
    }

    /// <summary>
    /// Looks for the named export with the binary search in the export name pointer table, which is ordered lexically
    /// by the specification. The result is the same as the first export with this name from <see cref="GetExports"/>, but
    /// the empty name is never found. The parsed stream should stay opened while the <see cref="Export.CreateStream"/>
    /// delegate is in use.
    /// </summary>
    public static bool TryGetExport(PeFile file, string name, [NotNullWhen(true)] out Export? export)
    {
      TryGetExport(file, name, false, out export);
      return export != null;
    }

    internal static bool TryGetExportLinear(PeFile file, string name, out Export? export) => TryGetExport(file, name, true, out export);

    private static bool TryGetExport(PeFile file, string name, bool isLinear, out Export? export)
    {
      export = null;
      var exportDirectory = file.ExportDirectory;
      if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size == 0)
        return false;

      var sections = file.Sections;
      var ied = ReadExportDirectory(sections, exportDirectory);
      var numberOfNames = EndianUtil.GetLeU4(ied.NumberOfNames);
      if (numberOfNames == 0)
        return false;

      var nameBytes = Encoding.UTF8.GetBytes(name);
      var buffer = new byte[nameBytes.Length + 1];
      using var namesStream = OpenStream(sections, EndianUtil.GetLeU4(ied.AddressOfNames), checked(numberOfNames * sizeof(uint)));

      uint found;
      if (isLinear)
        for (found = 0; found < numberOfNames && Compare(found) != 0; ++found)
        {
        }
      else
      {
        found = 0;
        for (var end = numberOfNames; found < end;)
        {
          var mid = found + (end - found) / 2;
          if (Compare(mid) > 0)
            found = mid + 1;
          else
            end = mid;
        }
      }

      if (found >= numberOfNames || nameBytes.Length == 0 || Compare(found) != 0)
        return false;

      ushort index;
      using (var ordinalStream = OpenStream(sections, checked(EndianUtil.GetLeU4(ied.AddressOfNameOrdinals) + found * sizeof(ushort)), sizeof(ushort)))
        index = ReadU2(ordinalStream);
      if (index >= EndianUtil.GetLeU4(ied.NumberOfFunctions))
        throw new FormatException("Invalid PE export name ordinal");

      uint functionVirtualAddress;
      using (var functionStream = OpenStream(sections, checked(EndianUtil.GetLeU4(ied.AddressOfFunctions) + (uint)index * sizeof(uint)), sizeof(uint)))
        functionVirtualAddress = ReadU4(functionStream);

      namesStream.Position = found * sizeof(uint);
      export = MakeExport(sections, exportDirectory, ReadString(sections, ReadU4(namesStream)), EndianUtil.GetLeU4(ied.Base) + index, functionVirtualAddress);
      return true;

      int Compare(uint nameIndex)
      {
        namesStream.Position = nameIndex * sizeof(uint);
        using var nameStream = OpenStream(sections, ReadU4(namesStream), 0);
        return StreamUtil.CompareStringZ(nameStream, nameBytes, buffer);
      }
    }

    private static unsafe IMAGE_EXPORT_DIRECTORY ReadExportDirectory(PeFile.Section[] sections, PeFile.DataDirectory exportDirectory)
    {
      IMAGE_EXPORT_DIRECTORY ied;
      using (var iedStream = OpenStream(sections, exportDirectory.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY)))
        StreamUtil.ReadBytes(iedStream, (byte*)&ied, sizeof(IMAGE_EXPORT_DIRECTORY));
      return ied;
    }

    private static Export MakeExport(PeFile.Section[] sections, PeFile.DataDirectory exportDirectory, string? name, uint ordinal, uint virtualAddress)
    {
      // Note: the forwarded export points to the forwarder string inside the export directory instead of the exported data
      if (exportDirectory.VirtualAddress <= virtualAddress && virtualAddress - exportDirectory.VirtualAddress < exportDirectory.Size)
        return new Export(name, ordinal, virtualAddress, ReadString(sections, virtualAddress), null);
      return new Export(name, ordinal, virtualAddress, null, MakeCreateStream(sections, virtualAddress));
    }

    private static string ReadString(PeFile.Section[] sections, uint virtualAddress)
    {
      using var stream = OpenStream(sections, virtualAddress, 0);
      return ReadStringZ(stream);
    }

    private static Stream OpenStream(PeFile.Section[] sections, uint virtualAddress, long minSize)
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

    private static PeFile.CreateStreamDelegate? MakeCreateStream(PeFile.Section[] sections, uint virtualAddress)
    {
      foreach (var section in sections)
        if (section.VirtualAddress <= virtualAddress && virtualAddress - section.VirtualAddress < Math.Max(section.VirtualSize, section.SizeOfRawData))
          return MakeSectionCreateStream(section, virtualAddress - section.VirtualAddress);
      return null;
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
      using var table = SymbolTable.Open(file);
      if (table == null)
        return true;

      var records = table.ReadRecords();
      fixed (byte* ptr = records)
        for (var n = 0u; n < table.Count; ++n)
        {
          var isym = table.Decode(ptr, ref n);
          if (!symbolFilter(table.MakeSymbol(isym)))
            return false;
        }

      return true;
    }

    /// <summary>
    /// Looks for the external symbol with the given name in the COFF symbol table, the symbols of other storage classes
    /// are skipped and the empty name is never found. The symbol definition is preferred to the undefined reference, then
    /// the lower symbol index wins. The COFF symbol table has no order to rely on, so it is scanned without decoding the
    /// names. The parsed stream should stay opened while the <see cref="Symbol.CreateStream"/> delegate is in use.
    /// </summary>
    public static unsafe bool TryGetSymbol(PeFile file, string name, [NotNullWhen(true)] out Symbol? symbol)
    {
      symbol = null;
      using var table = SymbolTable.Open(file);
      if (table == null)
        return false;

      var nameBytes = Encoding.UTF8.GetBytes(name);
      var buffer = new byte[nameBytes.Length + 1];
      IMAGE_SYMBOL? undefined = null;
      var records = table.ReadRecords();
      fixed (byte* ptr = records)
        for (var n = 0u; n < table.Count; ++n)
        {
          var isym = table.Decode(ptr, ref n);
          if ((IMAGE_SYM_CLASS)isym.StorageClass is not (IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_EXTERNAL or IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_WEAK_EXTERNAL))
            continue;
          var isDefined = (IMAGE_SYM)EndianUtil.GetLeU2(isym.SectionNumber) != IMAGE_SYM.IMAGE_SYM_UNDEFINED;
          if ((!isDefined && undefined != null) || !table.IsName(isym, nameBytes, buffer))
            continue;
          if (isDefined)
          {
            symbol = table.MakeSymbol(isym);
            return true;
          }

          undefined = isym;
        }

      if (undefined == null)
        return false;

      symbol = table.MakeSymbol(undefined.Value);
      return true;
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

    private static unsafe ushort ReadU2(Stream stream)
    {
      ushort value;
      StreamUtil.ReadBytes(stream, (byte*)&value, sizeof(ushort));
      return EndianUtil.GetLeU2(value);
    }

    private static unsafe uint ReadU4(Stream stream)
    {
      uint value;
      StreamUtil.ReadBytes(stream, (byte*)&value, sizeof(uint));
      return EndianUtil.GetLeU4(value);
    }

    private sealed class SymbolTable : IDisposable
    {
      private readonly PeFile.Section[] mySections;
      private readonly Stream myFileStream;
      private readonly Stream mySymStream;
      private readonly Stream myStrStream;
      private readonly uint myStrSize;
      internal readonly uint Count;

      private SymbolTable(PeFile.Section[] sections, Stream fileStream, Stream symStream, Stream strStream, uint strSize, uint count)
      {
        mySections = sections;
        myFileStream = fileStream;
        mySymStream = symStream;
        myStrStream = strStream;
        myStrSize = strSize;
        Count = count;
      }

      internal static unsafe SymbolTable? Open(PeFile file)
      {
        var pointerToSymbolTable = file.PointerToSymbolTable;
        var numberOfSymbols = file.NumberOfSymbols;
        if (pointerToSymbolTable == 0 || numberOfSymbols == 0)
          return null;

        var fileStream = file.CreateStream();
        try
        {
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

          return new SymbolTable(
            file.Sections,
            fileStream,
            new ReadOnlyNestedStream(fileStream, pointerToSymbolTable, symSize),
            new ReadOnlyNestedStream(fileStream, strOffset, strSize),
            strSize,
            numberOfSymbols);
        }
        catch
        {
          fileStream.Dispose();
          throw;
        }
      }

      public void Dispose()
      {
        mySymStream.Dispose();
        myStrStream.Dispose();
        myFileStream.Dispose();
      }

      internal byte[] ReadRecords()
      {
        mySymStream.Position = 0;
        return StreamUtil.ReadBytes(mySymStream, checked((int)mySymStream.Length));
      }

      internal unsafe IMAGE_SYMBOL Decode(byte* records, ref uint n)
      {
        IMAGE_SYMBOL isym;
        MemoryUtil.CopyBytes(records + n * sizeof(IMAGE_SYMBOL), (byte*)&isym, sizeof(IMAGE_SYMBOL));
        if (isym.NumberOfAuxSymbols >= Count - n)
          throw new FormatException("Invalid PE auxiliary symbol count");
        n += isym.NumberOfAuxSymbols;
        return isym;
      }

      internal unsafe bool IsName(IMAGE_SYMBOL isym, byte[] name, byte[] buffer)
      {
        if (name.Length == 0)
          return false;

        if (isym.Short == 0)
        {
          myStrStream.Position = CheckNameOffset(EndianUtil.GetLeU4(isym.Long));
          return StreamUtil.CompareStringZ(myStrStream, name, buffer) == 0;
        }

        // Note: the short name is not zero-terminated when it is exactly eight bytes long
        var shortName = (byte*)&isym;
        for (var n = 0; n < ImageSection.IMAGE_SIZEOF_SHORT_NAME; ++n)
        {
          if (shortName[n] == 0)
            return n == name.Length;
          if (n >= name.Length || shortName[n] != name[n])
            return false;
        }

        return name.Length == ImageSection.IMAGE_SIZEOF_SHORT_NAME;
      }

      internal unsafe Symbol MakeSymbol(IMAGE_SYMBOL isym)
      {
        string name;
        if (isym.Short == 0)
        {
          myStrStream.Position = CheckNameOffset(EndianUtil.GetLeU4(isym.Long));
          name = ReadStringZ(myStrStream);
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
          if (sectionNumber > mySections.Length)
            throw new FormatException("Invalid PE symbol section number");
          var section = mySections[sectionNumber - 1];
          if (value > Math.Max(section.VirtualSize, section.SizeOfRawData))
            throw new FormatException("Invalid PE symbol section offset");
          createStream = MakeSectionCreateStream(section, value);
        }

        return new Symbol(
          name,
          value,
          sectionNumber,
          (IMAGE_SYM_TYPE)(type & ImageSymbol.N_BTMASK),
          (IMAGE_SYM_DTYPE)(type >> ImageSymbol.N_BTSHFT),
          storageClass,
          isym.NumberOfAuxSymbols,
          createStream);

        static string GetName(byte* buf, int nameSize)
        {
          var blob = MemoryUtil.CopyBytes(buf, nameSize);
          return new string(Encoding.UTF8.GetChars(blob, 0, MemoryUtil.GetAsciiStringZSize(blob)));
        }
      }

      private uint CheckNameOffset(uint offset) => offset < myStrSize ? offset : throw new FormatException("Invalid PE symbol name offset");
    }
  }
}
