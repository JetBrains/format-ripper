using JetBrains.Annotations;

namespace JetBrains.SignatureVerifier.Elf
{
  public sealed class ElfInfo
  {
    public readonly ElfFlags EFlags;
    public readonly ElfClass EiClass;
    public readonly ElfData EiData;
    public readonly ElfOsAbi EiOsAbi;
    public readonly byte EiOsAbiVersion;
    public readonly ElfMachine EMachine;
    public readonly ElfType EType;

    [CanBeNull]
    public readonly string Interpreter;

    public ElfInfo(ElfClass eiClass,
      ElfData eiData,
      ElfOsAbi eiOsAbi,
      byte eiOsAbiVersion,
      ElfType eType,
      ElfMachine eMachine,
      ElfFlags eFlags,
      [CanBeNull] string interpreter)
    {
      EiClass = eiClass;
      EiData = eiData;
      EiOsAbi = eiOsAbi;
      EiOsAbiVersion = eiOsAbiVersion;
      EType = eType;
      EMachine = eMachine;
      EFlags = eFlags;
      Interpreter = interpreter;
    }
  }
}