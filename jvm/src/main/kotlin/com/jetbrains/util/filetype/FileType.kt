package com.jetbrains.util.filetype

enum class FileType(v: Int) {
  Unknown(0),
  Pe(1),
  Msi(2),
  MachO(3),
  Elf(4),
  ShebangScript(5)
}

