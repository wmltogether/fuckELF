# fuckELF
An Android ELF section patcher script

Auto adding new .rodata(.chstext) section to an ELF file

When I tried to translate a game , I found that Chinese strings are always longer than english or japanese utf-8 strings.
So , this script is useful for those games which has a smaller section in original ELF file.

p.s.
How to math the offset of strings in ELF:

1. Export .asm file using IDA Pro
2. Search strings in IDA (shift + f12)
3. you can find "off_2CB574	DCD unk_40B97C - 0x2CADE0 ; DATA XREF: .text:002CADC8r" in asm file
4. if string is unk_40B97C : 
      [long in off_2CB574] + 0x2CADE0 = 0x40B97C



