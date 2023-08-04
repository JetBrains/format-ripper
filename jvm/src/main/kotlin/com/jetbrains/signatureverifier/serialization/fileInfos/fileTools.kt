package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.ILogger
import org.jetbrains.annotations.NotNull
import java.nio.channels.SeekableByteChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption

private fun getProjectRootFromWorkingDirectory(): Path {
  val workingDirectory = Paths.get(System.getProperty("user.dir"))

  var current = workingDirectory
  while (current.parent != null) {
    if (Files.exists(current.resolve("gradle.properties"))) {
      return current
    }
    current = current.parent
  }

  error("Project root was not found from current working directory $workingDirectory")
}

private fun getTestDataDir(): Path {
  val projectRoot = getProjectRootFromWorkingDirectory()
  return projectRoot.parent.resolve("data")
}

fun getTestDataFile(dir: String, name: String): Path {
  val testDataFile = getTestDataDir().resolve(dir).resolve(name)
  if (Files.notExists(testDataFile)) {
    error("Test data file '$name' was not found at $testDataFile")
  }
  return testDataFile
}

fun getTestByteChannel(dir: String, name: String): SeekableByteChannel {
  return Files.newByteChannel(
      getTestDataFile(dir, name),
      setOf(StandardOpenOption.READ, StandardOpenOption.WRITE)
  )
}

class ConsoleLogger : ILogger {
  companion object {
    @JvmStatic
    val Instance = ConsoleLogger()
  }

  override fun Info(@NotNull str: String) = println("INFO: $str")
  override fun Warning(@NotNull str: String) = println("WARNING: $str")
  override fun Error(@NotNull str: String) = println("ERROR: $str")
  override fun Trace(@NotNull str: String) = println("TRACE: $str")
}