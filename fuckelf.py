# -*- coding: utf-8 -*-
from ctypes import *
import struct
import pprint
from cStringIO import StringIO
import os
class ProgramHeader:
    def __init__(self):
        self.p_type = None      # 00h Elf32_Word    , segment type
        self.p_offset = None    # 04h Elf32_Off     , segment offset
        self.p_vaddr = None     # 08h Elf32_Addr    , virtual address
        self.p_paddr = None     # 0ch Elf32_Addr    , physical address
        self.p_filesz = None    # 10h Elf32_Word    , number of bytes in file
        self.p_memsz = None     # 14h Elf32_Word    , number of bytes in mem
        self.p_flags = None     # 18h Elf32_Word    , flags
        self.p_align = None     # 1ch Elf32_Word    , memory alignment

class SectionHeader:
    def __init__(self):
        self.sh_name = None     # 00h Elf32_Word    , name
        self.sh_type = None     # 04h Elf32_Word    , type
        self.sh_flags = None
        self.sh_addr = None     # 10h Elf32_Word    , address
        self.sh_offset = None   # 14h Elf32_Word    , file offset
        self.sh_size = None     # 18h Elf32_Word    , section size
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None
        self.sh_entsize = None  # 24h Elf32_Word    , section entry size

class ReadELF:
    def __init__(self ):
        self.e_ident = None     # 00h unsigned char , ELF Identification
        self.e_type = None      # 10h Elf32_Half    , object file type
        self.e_machine = None   # 12h Elf32_Half    , machine
        self.e_version = None   # 14h Elf32_Word    , object file version
        self.e_entry = None     # 18h Elf32_Addr    , virtual entry point
        self.e_phoff = None     # 1ch Elf32_Off     , program header table offset
        self.e_shoff = None     # 20h Elf32_Off     , section header table offset
        self.e_flag = None      # 24h Elf32_Word    , processor-specific flags
        self.e_ensize = None    # 28h Elf32_Half    , ELF Header size
        self.e_phentsize = None # 2ah Elf32_Half    , program header entry size
        self.e_phnum = None     # 2ch Elf32_Half    , number of program header entries
        self.e_shentsize = None # 2eh Elf32_Half    , section header entry size
        self.e_shnum = None     # 30h Elf32_Half    , number of section header entries
        self.e_shstrndx = None  # 32h Elf32_Half    , section header table's "section header string table" entry offset
        self.e_fullMemorySize = None
        self.e_SectionStringTableOffset = None
        self.e_shstrIndexOffset = None # Point to shstr Index Address
        self.e_firstPT_LOAD_OFFSET = None


    def ReadElfInfo(self ,elf_name):
        fp = open(elf_name , 'rb')
        fp.seek(0x10)
        (self.e_type , self.e_machine , \
            self.e_version , self.e_entry , self.e_phoff , \
            self.e_shoff , self.e_flag , self.e_ensize ,\
            self.e_phentsize , self.e_phnum , self.e_shentsize ,\
            self.e_shnum , self.e_shstrndx )= struct.unpack("HHIIIIIHHHHHH" ,fp.read(0x24))
        fp.seek(self.e_phoff)
        for i in xrange(self.e_phnum):
            pHeader = ProgramHeader()
            (pHeader.p_type , pHeader.p_offset , pHeader.p_vaddr , pHeader.p_paddr , \
                pHeader.p_filesz , pHeader.p_memsz ,pHeader.p_flags, pHeader.p_align) = struct.unpack("8I" ,fp.read(0x20))
            if pHeader.p_type == 1 and pHeader.p_flags == 5:
                # get PT_LOAD
                self.e_firstPT_LOAD_OFFSET = fp.tell() - 0x20
            if pHeader.p_type == 1 and pHeader.p_flags == 6:
                # get full memory length of ELF
                self.e_fullMemorySize = ((pHeader.p_vaddr + pHeader.p_memsz)%pHeader.p_align | 1) * pHeader.p_align
        fp.seek(self.e_shoff + self.e_shstrndx * self.e_shentsize)
        self.e_shstrIndexOffset = self.e_shoff + self.e_shstrndx * self.e_shentsize
        shHeader = SectionHeader()
        (shHeader.sh_name ,
             shHeader.sh_type ,
             shHeader.sh_flags ,
             shHeader.sh_addr ,
             shHeader.sh_offset ,
             shHeader.sh_size,
             shHeader.sh_link,
             shHeader.sh_info ,
             shHeader.sh_addralign,
             shHeader.sh_entsize) = struct.unpack("10I" ,fp.read(0x28))
        fp.seek(shHeader.sh_offset)
        self.e_SectionStringTableOffset = shHeader.sh_offset
        SectionStringTable = fp.read(shHeader.sh_size)
        fp.seek(self.e_shoff)

        for i in xrange(self.e_shnum):
            shHeader = SectionHeader()
            (shHeader.sh_name ,
             shHeader.sh_type ,
             shHeader.sh_flags ,
             shHeader.sh_addr ,
             shHeader.sh_offset ,
             shHeader.sh_size,
             shHeader.sh_link,
             shHeader.sh_info ,
             shHeader.sh_addralign,
             shHeader.sh_entsize) = struct.unpack("10I" ,fp.read(0x28))

    def GetElfInfo(self ,elf_name):
        print("#### Current ELF:%s ####"%elf_name)
        fp = open(elf_name , 'rb')
        fp.seek(0x10)
        (self.e_type , self.e_machine , \
            self.e_version , self.e_entry , self.e_phoff , \
            self.e_shoff , self.e_flag , self.e_ensize ,\
            self.e_phentsize , self.e_phnum , self.e_shentsize ,\
            self.e_shnum , self.e_shstrndx )= struct.unpack("HHIIIIIHHHHHH" ,fp.read(0x24))

        pprint.pprint("program header table offset :0x%08x ,"%self.e_phoff)
        pprint.pprint("program header entry size :0x%08x ,"%self.e_phentsize)
        pprint.pprint("number of program header entries :0x%08x ,"%self.e_phnum)
        pprint.pprint("section header table offset :0x%08x ,"%self.e_shoff)
        pprint.pprint("section header entry size :0x%08x ,"%self.e_shentsize)
        pprint.pprint("number of section header entries :0x%08x ,"%self.e_shnum)
        pprint.pprint("ELF Header size             :0x%08x ,"%self.e_ensize)
        print("####\n#### program header:%08x ####\n  TYPE  \t  OFFSET  \t  VADDR  \t  PADDR  \tFILESIZE\tMEMORYSIZE\tFLAGS\t  ALIGN"%self.e_phoff)
        fp.seek(self.e_phoff)
        for i in xrange(self.e_phnum):
            pHeader = ProgramHeader()
            (pHeader.p_type , pHeader.p_offset , pHeader.p_vaddr , pHeader.p_paddr , \
                pHeader.p_filesz , pHeader.p_memsz ,pHeader.p_flags, pHeader.p_align) = struct.unpack("8I" ,fp.read(0x20))
            if pHeader.p_type == 1 and pHeader.p_flags == 5:
                # get PT_LOAD
                self.e_firstPT_LOAD_OFFSET = fp.tell() - 0x20
            if pHeader.p_type == 1 and pHeader.p_flags == 6:
                # get full memory length of ELF
                self.e_fullMemorySize = ((pHeader.p_vaddr + pHeader.p_memsz)%pHeader.p_align | 1) * pHeader.p_align
            print("%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x"%(pHeader.p_type , pHeader.p_offset , pHeader.p_vaddr , pHeader.p_paddr , \
                                                                    pHeader.p_filesz , pHeader.p_memsz ,pHeader.p_flags, pHeader.p_align))
        fp.seek(self.e_shoff + self.e_shstrndx * self.e_shentsize)
        shHeader = SectionHeader()
        (shHeader.sh_name ,
             shHeader.sh_type ,
             shHeader.sh_flags ,
             shHeader.sh_addr ,
             shHeader.sh_offset ,
             shHeader.sh_size,
             shHeader.sh_link,
             shHeader.sh_info ,
             shHeader.sh_addralign,
             shHeader.sh_entsize) = struct.unpack("10I" ,fp.read(0x28))
        fp.seek(shHeader.sh_offset)
        SectionStringTable = fp.read(shHeader.sh_size)
        fp.seek(self.e_shoff)

        print("####\n#### section header:%08x ####\nNAME\n  TYPE  \tFLAGS\tADDR\t  OFFSET  \t  SIZE  \t  LINK  \tINFO\t  ALIGN \tENTSIZE"%self.e_shoff)
        for i in xrange(self.e_shnum):
            shHeader = SectionHeader()
            (shHeader.sh_name ,
             shHeader.sh_type ,
             shHeader.sh_flags ,
             shHeader.sh_addr ,
             shHeader.sh_offset ,
             shHeader.sh_size,
             shHeader.sh_link,
             shHeader.sh_info ,
             shHeader.sh_addralign,
             shHeader.sh_entsize) = struct.unpack("10I" ,fp.read(0x28))
            print("%s\n%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x"%(SectionStringTable[shHeader.sh_name:].split("\x00")[0] ,
                                                                    shHeader.sh_type ,
                                                                    shHeader.sh_flags ,
                                                                    shHeader.sh_addr ,
                                                                    shHeader.sh_offset ,
                                                                    shHeader.sh_size,
                                                                    shHeader.sh_link,
                                                                    shHeader.sh_info ,
                                                                    shHeader.sh_addralign,
                                                                    shHeader.sh_entsize))
        print("end of section header:%08x"%fp.tell())
        fp.close()

class FuckELF:
    def __init__(self):
        self.new_section_name = ".chstext"
        self.new_section_name_pos = 0
        self.new_type = 1
        self.new_flags = 2
        self.new_sh_addr = 0
        self.new_sh_offset = None
        self.new_sh_size = 0x100000
        self.new_sh_link = 0
        self.new_sh_info = 0
        self.new_sh_addralign = 4
        self.new_sh_entsize = 0
        self.e_fullMemorySize = None
        self.e_SectionStringTableOffset = None
        self.e_shstrIndexOffset = None
        self.e_firstPT_LOAD_OFFSET = None



    def addNewELFSectionTable(self , elfBuffer):
        print("Extending Section Table")
        elfBuffer.seek(0x10 + 0x20 ,0)
        count, = struct.unpack("I" , elfBuffer.read(4))#GET e_shnum
        elfBuffer.seek(0,2)
        self.new_sh_addr = self.e_fullMemorySize + 0x10
        self.new_section_name_pos = self.e_fullMemorySize - self.e_SectionStringTableOffset
        elfBuffer.write(struct.pack("10I" , self.new_section_name_pos ,
                                            self.new_type ,
                                            self.new_flags ,
                                            self.e_fullMemorySize + 0x10 ,
                                            self.e_fullMemorySize + 0x10 ,
                                            self.new_sh_size ,
                                            self.new_sh_link ,
                                            self.new_sh_info ,
                                            self.new_sh_addralign ,
                                            self.new_sh_entsize))
        elfBuffer.seek(self.e_shstrIndexOffset)
        elfBuffer.seek(20,1)
        elfBuffer.write(struct.pack("I" ,(self.new_sh_addr - self.e_SectionStringTableOffset)))

    def addMemoryAlign(self , elfBuffer):
        print("Patching Memory Alignment")
        elfBuffer.seek(0,2)
        tmp_pos = elfBuffer.tell()
        elfBuffer.write("\x00" * (self.e_fullMemorySize - tmp_pos))
        elfBuffer.seek(0,2)


    def addNewSection(self , elfBuffer):
        print("Adding New Section:%s"%self.new_section_name)
        newLength = len(self.new_section_name) + self.new_sh_size
        newSectionData = self.new_section_name
        newSectionData += "\x00" * (0x10 - len(self.new_section_name))
        newSectionData += "\x00" * (self.new_sh_size)
        elfBuffer.seek(0,2)
        elfBuffer.write(newSectionData)

    def patchELFSectionCount(self , elfBuffer):
        elfBuffer.seek(0x10 + 0x20 ,0)
        count, = struct.unpack("H" , elfBuffer.read(2))#GET e_shnum
        print("Patch :%08x   set count:%d >>>> to >>>>%d"%(0x30 , count , count + 1))
        elfBuffer.seek(-2,1)
        elfBuffer.write(struct.pack("H" , count + 1))#SET e_shnum + 1

    def patchProgramHeaderInfo(self , elfBuffer):
        elfBuffer.seek(0,2)
        buffer_end = elfBuffer.tell()
        elfBuffer.seek(self.e_firstPT_LOAD_OFFSET + 0x10)
        print("Patch :%08x  >>> ELF SIZE :%08x"%(self.e_firstPT_LOAD_OFFSET + 0x10 , buffer_end))
        elfBuffer.write(struct.pack("I" , buffer_end))
        elfBuffer.write(struct.pack("I" , buffer_end))

    def fuckELFfile(self ,elfname):
        readElf = ReadELF()
        readElf.ReadElfInfo(elfname) #read ELF Header info
        self.e_fullMemorySize = readElf.e_fullMemorySize #Get full ELF size in memory
        self.e_SectionStringTableOffset = readElf.e_SectionStringTableOffset #Get Section String Table offset
        self.e_shstrIndexOffset = readElf.e_shstrIndexOffset
        self.e_firstPT_LOAD_OFFSET = readElf.e_firstPT_LOAD_OFFSET
        elfBuffer = StringIO()
        elffile = open(elfname , 'rb')
        elfBuffer.write(elffile.read())
        elfBuffer.seek(0)
        elffile.close()
        self.addNewELFSectionTable(elfBuffer)
        self.addMemoryAlign(elfBuffer)
        self.addNewSection(elfBuffer)
        self.patchELFSectionCount(elfBuffer)
        self.patchProgramHeaderInfo(elfBuffer)
        elfBuffer.seek(0,2)
        new_elf_data = elfBuffer.getvalue()
        dest = open(elfname[:-3] + "_mod.so", 'wb')
        dest.write(new_elf_data)
        dest.close()

def main():
    readElf = ReadELF()
    readElf.GetElfInfo("libApplicationMain.so")
    fuckELF = FuckELF()
    fuckELF.fuckELFfile("libApplicationMain.so")

if __name__ == '__main__':
    main()
    os.system("pause")

