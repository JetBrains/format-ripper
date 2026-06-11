using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public static class UnityUtil
  {
    public const string UNITY_SCRIPTING_BACKEND_ELF_SYMBOL = "UnityScriptingBackend";
    public const string UNITY_SCRIPTING_BACKEND_MACHO_PE_SYMBOL = "_" + UNITY_SCRIPTING_BACKEND_ELF_SYMBOL;

    public const string CORECLR_UNITY_SCRIPTING_BACKEND_VALUE = "CoreCLR";
    public const string IL2CPP_UNITY_SCRIPTING_BACKEND_VALUE = "IL2CPP";
    public const string MONO_UNITY_SCRIPTING_BACKEND_VALUE = "Mono";
  }
}