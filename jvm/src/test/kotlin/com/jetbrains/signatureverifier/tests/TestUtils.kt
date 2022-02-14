package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.ReadToEnd
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel
import java.io.FileInputStream
import java.io.InputStream
import java.nio.channels.SeekableByteChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption

object TestUtil {
  fun getTestByteChannel(dir: String, name: String): SeekableByteChannel {
    return Files.newByteChannel(getTestDataFile(dir, name), StandardOpenOption.READ)
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
    val projectRoot = getProjectRootFromWorkingDirectory()
    val testDataFile = projectRoot.parent.resolve("data").resolve(dir).resolve(name)
    if (Files.notExists(testDataFile)) {
      error("Test data file '$name' was not found at $testDataFile")
    }
    return testDataFile
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
}