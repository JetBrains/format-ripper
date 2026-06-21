#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;

namespace JetBrains.Tests
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum ResourceCategory
  {
    Dmg,
    Elf,
    MachO,
    Misc,
    Msi,
    Pe,
    PowerShell,
    Sh
  }

  internal static class TestDataUtil
  {
    private const string MarkerFileName = ".test-data-root";
    private const string DirectoryName = "data";
    private const string EnvironmentVariableName = "JB_TEST_DATA";

    private static string GetCategoryDirectoryName(ResourceCategory category) => category switch
      {
        ResourceCategory.Dmg => "dmg",
        ResourceCategory.Elf => "elf",
        ResourceCategory.MachO => "mach-o",
        ResourceCategory.Misc => "misc",
        ResourceCategory.Msi => "msi",
        ResourceCategory.Pe => "pe",
        ResourceCategory.PowerShell => "powershell",
        ResourceCategory.Sh => "sh",
        _ => throw new ArgumentOutOfRangeException(nameof(category), category, null)
      };

    internal static Stream OpenRead(ResourceCategory category, string resourceName) => File.OpenRead(GetPath(category, resourceName));

    internal static void OpenRead(ResourceCategory category, string resourceName, Action<Stream> handler, Action<string>? onMissingResource = null)
    {
      var path = TryGetPath(category, resourceName);
      if (path == null)
      {
        var str = GetMissingFileMessage(category, resourceName);
        onMissingResource?.Invoke(str);
        throw new InvalidOperationException(str);
      }

      using var stream = File.OpenRead(path);
      handler(stream);
    }

    internal static TResult OpenRead<TResult>(ResourceCategory category, string resourceName, Func<Stream, TResult> handler)
    {
      using var stream = File.OpenRead(GetPath(category, resourceName));
      return handler(stream);
    }

    private static string GetPath(ResourceCategory category, string resourceName) => TryGetPath(category, resourceName) ?? throw new InvalidOperationException(GetMissingFileMessage(category, resourceName));

    private static string? TryGetPath(ResourceCategory category, string resourceName) => GetProbedPaths(category, resourceName).FirstOrDefault(File.Exists);

    private static string[] GetProbedPaths(ResourceCategory category, string resourceName)
    {
      var roots = Roots;
      var categoryDirectoryName = GetCategoryDirectoryName(category);
      var name = resourceName.Replace('/', Path.DirectorySeparatorChar);
      var paths = new string[roots.Length];
      for (var n = 0; n < roots.Length; ++n)
        paths[n] = Combine(roots[n], categoryDirectoryName, name);
      return paths;
    }

    private static string GetMissingFileMessage(ResourceCategory category, string resourceName) => "Missing test data file " + Combine(GetCategoryDirectoryName(category), resourceName);

    private static readonly StringComparison ourPathComparison = Path.DirectorySeparatorChar == '\\'
      ? StringComparison.OrdinalIgnoreCase
      : StringComparison.Ordinal;

    private static readonly object ourRootsLock = new();
    private static string[]? ourRoots;

    private static string[] Roots
    {
      get
      {
        lock (ourRootsLock)
          return ourRoots ??= FindRoots().ToArray();
      }
    }

    private static IEnumerable<string> FindRoots()
    {
      var primaryRoot = FindPrimaryRoot();
      ValidateRoot(primaryRoot);
      yield return primaryRoot;

      var additionalRoot = Path.GetFullPath(Combine(primaryRoot, "..", "..", DirectoryName));
      if (Directory.Exists(additionalRoot))
      {
        ValidateRoot(additionalRoot);
        yield return additionalRoot;
      }
    }

    private static string FindPrimaryRoot()
    {
      var fromEnvironment = Environment.GetEnvironmentVariable(EnvironmentVariableName);
      if (fromEnvironment != null && fromEnvironment.Trim().Length > 0)
      {
        var path = fromEnvironment.Trim();
        if (!IsAbsolutePath(path))
          throw new InvalidOperationException($"The {EnvironmentVariableName} environment variable should contain an absolute path to the test data directory, but was {path}");
        var root = Path.GetFullPath(path);
        if (!Directory.Exists(root))
          throw new InvalidOperationException($"The {EnvironmentVariableName} environment variable points to the missing test data directory {root}");
        return root;
      }

      foreach (var startDirectory in GetStartDirectories())
        for (var current = new DirectoryInfo(startDirectory); current != null; current = current.Parent)
        {
          var candidate = Path.Combine(current.FullName, DirectoryName);
          if (Directory.Exists(candidate))
            return candidate;
        }

      throw new InvalidOperationException($"Failed to find the {DirectoryName} test data directory, set the {EnvironmentVariableName} environment variable to point to it.");
    }

    private static IEnumerable<string> GetStartDirectories()
    {
      var baseDirectory = TrimSeparators(AppDomain.CurrentDomain.BaseDirectory);
      if (baseDirectory.Length > 0)
        yield return baseDirectory;

      var currentDirectory = TrimSeparators(Directory.GetCurrentDirectory());
      if (currentDirectory.Length > 0 && !string.Equals(currentDirectory, baseDirectory, ourPathComparison))
        yield return currentDirectory;
    }

    private static void ValidateRoot(string root)
    {
      if (!File.Exists(Path.Combine(root, MarkerFileName)))
        throw new InvalidOperationException($"The test data directory {root} has no {MarkerFileName} marker file");
    }

    private static bool IsAbsolutePath(string path)
    {
      if (!Path.IsPathRooted(path))
        return false;
      if (Path.DirectorySeparatorChar != '\\')
        return true;
      return path.Length >= 3 && path[1] == ':' && IsSeparator(path[2]) ||
             path.Length >= 2 && IsSeparator(path[0]) && IsSeparator(path[1]);
    }

    private static bool IsSeparator(char c) => c == Path.DirectorySeparatorChar || c == Path.AltDirectorySeparatorChar;

    private static string TrimSeparators(string? path)
    {
      if (path == null)
        return "";
      var trimmed = path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
      return trimmed.Length > 0 ? trimmed : path;
    }

    private static string Combine(string path, params string[] parts) => parts.Aggregate(path, Path.Combine);
  }
}