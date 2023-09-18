package com.jetbrains.util

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel
import java.io.FileInputStream
import java.io.InputStream
import java.nio.channels.SeekableByteChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.*

internal object TestUtil {
  fun getTestByteChannel(name: String): SeekableByteChannel {
    return Files.newByteChannel(getTestDataFile(name), StandardOpenOption.READ)
  }

  fun getTestByteChannel(
    dir: String,
    name: String,
    write: Boolean = false
  ): SeekableByteChannel {
    val params = mutableSetOf(StandardOpenOption.READ)
    if (write)
      params.add(StandardOpenOption.WRITE)
    return Files.newByteChannel(getTestDataFile(dir, name), params)
  }

  fun getTestByteChannelCopy(dir: String, name: String): SeekableByteChannel {
    getTestByteChannel(dir, name).use {
      return SeekableInMemoryByteChannel(it.ReadToEnd())
    }
  }

  fun getTestDataInputStream(dir: String, name: String): InputStream {
    return FileInputStream(getTestDataFile(dir, name).toFile())
  }

  fun getTestDataFile(dir: String, name: String): Path {
    val testDataFile = getTestDataDir().resolve(dir).resolve(name)
    if (Files.notExists(testDataFile)) {
      error("Test data file '$name' was not found at $testDataFile")
    }
    return testDataFile
  }

  fun getTestDataFile(name: String): Path {
    val getTestDataDir = getTestDataDir()
    val path =
      Files.walk(getTestDataDir, 2).filter { path -> path.fileName.toString() == name }.findFirst()
    if (path.isEmpty) {
      error("Test data file '$name' was not found at $getTestDataDir")
    }
    return path.get()
  }

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

  internal inline fun <reified T : Enum<T>?> enumSetOf(vararg items: T): EnumSet<T> {
    return EnumSet.noneOf(T::class.java).apply { addAll(items) }
  }
}