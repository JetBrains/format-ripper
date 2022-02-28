package com.jetbrains.util.filetype.elf

enum class ElfClass(v: Byte) {
  ELFCLASSNONE(0),
  ELFCLASS32(1),
  ELFCLASS64(2)
}


enum class ElfData(v: Byte) {
  ELFDATANONE(0),
  ELFDATA2LSB(1),
  ELFDATA2MSB(2)
}


enum class ElfVersion(val v: Byte) {
  EV_NONE(0),
  EV_CURRENT(1);

  companion object {
    fun fromValue(v: Byte) = values().first { it.v == v }
  }
}


enum class ElfOsAbi(val v: Byte) {
  ELFOSABI_NONE(0),
  ELFOSABI_HPUX(1),
  ELFOSABI_NETBSD(2),
  ELFOSABI_LINUX(3),
  ELFOSABI_HURD(4),
  ELFOSABI_86OPEN(5),
  ELFOSABI_SOLARIS(6),
  ELFOSABI_AIX(7),
  ELFOSABI_IRIX(8),
  ELFOSABI_FREEBSD(9),
  ELFOSABI_TRU64(10),
  ELFOSABI_MODESTO(11),
  ELFOSABI_OPENBSD(12),
  ELFOSABI_OPENVMS(13),
  ELFOSABI_NSK(14),
  ELFOSABI_AROS(15),
  ELFOSABI_FENIXOS(16),
  ELFOSABI_CLOUDABI(17),
  ELFOSABI_OPENVOS(18);

  companion object {
    fun fromValue(v: Byte) = values().first { it.v == v }
  }
}


enum class ElfType(val v: Int) {
  ET_NONE(0),
  ET_REL(1),
  ET_EXEC(2),
  ET_DYN(3),
  ET_CORE(4),
  ET_LOOS(0xfe00),
  ET_HIOS(0xfeff),
  ET_LOPROC(0xff00),
  ET_HIPROC(0xffff);

  companion object {
    fun fromValue(v: Int) = values().first { it.v == v }
  }
}


enum class ElfMachine(val v: Int) {
  EM_NONE(0),
  EM_M32(1),
  EM_SPARC(2),
  EM_386(3),
  EM_68K(4),
  EM_88K(5),
  EM_IAMCU(6),
  EM_860(7),
  EM_MIPS(8),
  EM_S370(9),
  EM_MIPS_RS3_LE(10),
  EM_PARISC(15),
  EM_VPP500(17),
  EM_SPARC32PLUS(18),
  EM_960(19),
  EM_PPC(20),
  EM_PPC64(21),
  EM_S390(22),
  EM_V800(36),
  EM_FR20(37),
  EM_RH32(38),
  EM_RCE(39),
  EM_ARM(40),
  EM_SH(42),
  EM_SPARCV9(43),
  EM_TRICORE(44),
  EM_ARC(45),
  EM_H8_300(46),
  EM_H8_300H(47),
  EM_H8S(48),
  EM_H8_500(49),
  EM_IA_64(50),
  EM_MIPS_X(51),
  EM_COLDFIRE(52),
  EM_68HC12(53),
  EM_MMA(54),
  EM_PCP(55),
  EM_NCPU(56),
  EM_NDR1(57),
  EM_STARCORE(58),
  EM_ME16(59),
  EM_ST100(60),
  EM_TINYJ(61),
  EM_X86_64(62),
  EM_PDSP(63),
  EM_FX66(66),
  EM_ST9PLUS(67),
  EM_ST7(68),
  EM_68HC16(69),
  EM_68HC11(70),
  EM_68HC08(71),
  EM_68HC05(72),
  EM_SVX(73),
  EM_ST19(74),
  EM_VAX(75),
  EM_CRIS(76),
  EM_JAVELIN(77),
  EM_FIREPATH(78),
  EM_ZSP(79),
  EM_MMIX(80),
  EM_HUANY(81),
  EM_PRISM(82),
  EM_AVR(83),
  EM_FR30(84),
  EM_D10V(85),
  EM_D30V(86),
  EM_V850(87),
  EM_M32R(88),
  EM_MN10300(89),
  EM_MN10200(90),
  EM_PJ(91),
  EM_OPENRISC(92),
  EM_ARC_A5(93),
  EM_XTENSA(94),
  EM_VIDEOCORE(95),
  EM_TMM_GPP(96),
  EM_NS32K(97),
  EM_TPC(98),
  EM_SNP1K(99),
  EM_ST200(100),
  EM_IP2K(101),
  EM_MAX(102),
  EM_CR(103),
  EM_F2MC16(104),
  EM_MSP430(105),
  EM_BLACKFIN(106),
  EM_SE_C33(107),
  EM_SEP(108),
  EM_ARCA(109),
  EM_UNICORE(110),
  EM_AARCH64(183),
  EM_RISCV(243),
  EM_ALPHA_STD(41),
  EM_ALPHA(0x9026);

  companion object {
    fun fromValue(v: Int) = values().first { it.v == v }
  }
}

class ElfSegmentType(val v: Int) {
  companion object {
    val PT_INTERP = 3
  }
}

