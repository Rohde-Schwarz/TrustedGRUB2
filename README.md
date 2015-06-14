**Unfortunately i had to force push to be able to update to more recent versions of GRUB2. The GRUB2 commit history is now part of this repository. Sorry for the inconvenience. This should be the first and last time this had happened.**


# TrustedGRUB2

[![Build Status](https://travis-ci.org/Sirrix-AG/TrustedGRUB2.svg)](https://travis-ci.org/Sirrix-AG/TrustedGRUB2)

## 1. General Information

### 1.1 Introduction

This file describes the extensions made to transform a standard GRUB2 into a version that offers TCG (TPM) support for granting the integrity of the boot process (trusted boot). This project was highly inspired by the former projects [TrustedGrub1](https://www.sirrix.com/content/pages/trustedgrub_en.htm) and GRUB-IMA. However TrustedGRUB2 was completely written from scratch.

TrustedGRUB2 is measuring all critical components during the boot process, i.e. GRUB2 kernel, GRUB2 modules, the OS kernel or OS modules and so on, together with their
parameters. Please note that the TrustedGRUB2 MBR bootcode has not to be checked here (it wouldn't even be possible). The MBR bootcode has already been measured by the TPM itself.
Since the TPM is passive, it has no direct ability to check if the integrity of bootloader (and the OS kernel/modules and so on) actually is correct.
This can only be done indirectly by using the seal/unseal functions of the TPM (for details on this topic, you should have a look at the TCG specifications or on other documents describing TCG/TPM abilities).

### 1.2 Features

* Based on GRUB2 Release 2.00
* TPM Support with TPM detection (only legacy/mbr mode, UEFI is not supported at the moment)
* Measurement of GRUB2 kernel
* Measurement of all loaded GRUB2 modules
* Measurement of all commands and their parameters entered in shell and scripts
* New SHA1-implementation in GRUB2 kernel (necessary for doing the GRUB2 modules measurement as the crypto module isn't loaded at this stage)
* Added LUKS keyfile support with additional parameter "-k KEYFILE" for cryptomount command
* Added supported for unsealing LUKS keyfile with additional "-s" parameter for cryptomount command. LUKS-header is measured before unsealing into PCR 12. Currently unsealing only supported with SRK and well known secret (20 zero bytes)
* New commands:
  * readpcr PCRNUM
  * tcglog LOGINDEX
  * measure FILE PCRNUM
  * setmor DISABLEAUTODETECT
* Loader measurements:
  * linux / linux16
  * initrd / initrd16
  * chainloader
  * ntdlr
* New cryptomount parameters:
  * cryptomount -k KEYFILE
  * cryptomount -k KEYFILE -s
* Functionality added without own command:
  * TPM_Unseal
  * TPM_GetRandom
  * TPM_OIAP
  * TPM_OSAP

### 1.3 Measurements (in short)

* PCR 8 First sector of TrustedGRUB2 kernel (diskboot.img)
* PCR 9 TrustedGRUB2 kernel (core.img)
* PCR 10 Everything that is loaded from disk (grub2-modules,
Linux-kernel, initrd, ntldr, etc.) // TODO: fonts, themes, locales
* PCR 11 contains all commandline arguments from scripts (e.g. grub.cfg)
and those entered in the shell
* PCR 12 LUKS-header

Kernel measurements are only implemented for diskboot so far (e.g. no cdboot or pxeboot measurement)

### 1.4 Requirements

In order to use the TCG-enhanced TrustedGRUB2, you need a computer which has TCG enhancements according to TCG specs. v1.2, since SHA1-calculations are extended into PC-Registers of the TPM.

### 1.5 Known Bugs / Limitations

* On some HP notebooks and workstations, TrustedGRUB2 is not able to do the kernel measurements due to a buggy BIOS. This means PCR 8,9 can contain bogus values. This seems to be especially the case if the core.img is bigger than 64KB.

If you find any bugs, create an issue or send a mail to trustedgrub@sirrix.com

### 1.6 Configuring TrustedGRUB2 before installation

#### 1.6.1 PCR selection
PCR selection for module measurement, command measurement and loaded files measurement can be adjusted in tpm.h:

```C++
#define TPM_LOADED_FILES_PCR 10
#define TPM_COMMAND_MEASUREMENT_PCR 11
#define TPM_LUKS_HEADER_MEASUREMENT_PCR 12
```

#### 1.6.2 Debug output

To enable some debug output uncomment:

```C++
/* #define TGRUB_DEBUG */
```

in tpm.h

### 1.7 Installation of TrustedGRUB2

Required Packages for compiling:
* autogen
* autoconf
* automake
* gcc
* bison
* flex

To compile and install TrustedGRUB2, please run

```bash
./autogen.sh
./configure --prefix=INSTALLDIR --target=i386 -with-platform=pc --disable-werror
make
make install
```

Installing to device:

```bash
./INSTALLDIR/sbin/grub-install --directory=INSTALLDIR/lib/grub/i386-pc /dev/sda
```

[WARNING]
if installing over an old GRUB2 install you probably have to adjust your grub.cfg

For usb-devices this command can be used (assuming /dev/sdb/ is your usb-device):

```bash
./INSTALLDIR/sbin/grub-install --directory=INSTALLDIR/lib/grub/i386-pc --root-directory=/mnt/sdb1 /dev/sdb
```

## 2. Technical Details

### 2.1 General view on how TrustedGRUB2 works

The goal of TrustedGRUB2 is to accomplish a chain of trust, i.e. every component measures the integrity of the succeeding component.
Concretely, this looks like the following:

|         Component							   |		measured by              |
| -------------------------------------------  |  ----------------------------- |
| BIOS                  					   | CRTM					|
| TrustedGRUB2 MBR bootcode    				   | BIOS					|
| start of TrustedGRUB2 kernel (diskboot.img)  | TrustedGRUB2 MBR bootcode		|
| rest of TrustedGRUB2 kernel (core.img)	   | start of TrustedGRUB2 kernel	|
| Grub modules + OS (kernel and so on) 		   | TrustedGRUB2 kernel			|

This chain of trust can be extended by using the newly added "measure" command to measure the integrity of arbitrary files.

### 2.2 Measurement of GRUB2 kernel

#### 2.2.1 Modifications in boot.S (MBR bootcode)

GRUB2 MBR bootcode is already measured by the TPM. The MBR bootcode has the task to load first sector of TrustedGRUB2 kernel (diskboot.img). Diskboot.img itself loads the rest of GRUB2 kernel.
Therefore GRUB2 MBR code is extended to measure diskboot.img before jumping to it:

1. Diskboot.img is hashed with a SHA-1 algorithm. Diskboot.img is loaded at address 0x8000, its length is 512 bytes.
2. The resulting hash value is written to PCR (Platform Configuration Register) 8. More precisely, the former content of this register (which actually is 0) is concatenated to the new value, then hashed with SHA1 and finally written again to PCR 8

Due to the PC architecture, the size of the MBR (where TrustedGRUB2 boot.S is
located) is limited to 512 bytes. But the original GRUB2 MBR bootcode is already very
close to this limit, leaving very few space for the TCG extensions. Because
of this, it was necessary (in the current version of TrustedGRUB2) to eliminate the CHS-code.
This results in the problem that we support only LBA-discs now. FDD boot is not possible.

#### 2.2.2 Modifications in diskboot.S

boot.S contains the code for loading the first sector of TrustedGRUB2 kernel (diskboot.img). Its only task
is the load the rest of TrustedGRUB2 kernel. Therefore, the TCG extension now has to measure the rest of TrustedGRUB2 kernel
The changes here are widely the same as in TrustedGRUB2 bootcode, with the differences that
the entry point for the code which has to be checked is a address 0x8200 and that the result is written into PCR 9.

### 2.3 Measurement of GRUB2 modules

Grub2 has a modular structure. GRUB2 dynamically loads needed modules which are not contained in kernel. Modifications in boot.S and diskboot.S are only measuring GRUB2 kernel.
Therefore the GRUB2 module loader was modified to measure modules to PCR 10 before they are loaded. Changes can be found in dl.c .

### 2.4 New SHA1-implementation in GRUB2 kernel

In order to make GRUB2 modules measurement possible, a SHA1-implementation had to be added to the kernel.
GRUB2 already contains an SHA1-implementation in its crypto module, but this isn't loaded at this stage.

### 2.5 Measurement of all commands and their parameters entered in shell and scripts

All commands which are entered in shell or executed by scripts is measured to PCR 11. Therefore commands in grub.cfg are automatically measured. No need to measure grub.cfg separately.
One exception applies to this rule: The "menuentry" command is not measured because it makes precomputation of the PCR value difficult and is unnecessary because each command within the menuentry is anyway measured.

### 2.6 TrustedGRUB2 commands

#### 2.6.1 new commands

```
readpcr PCRNUM
```

Display current value of the PCR (Platform Configuration Register) within TPM (Trusted Platform Module) at index, `PCRNUM`.  
<br>  
<br>  

```
tcglog LOGINDEX
```

Displays TCG event log entry at position, `LOGINDEX`. Type in "0" for all entries.  
<br>  
<br>  

```
measure FILE PCRNUM
```

Perform TCG measurement operation with the file `FILE` and with PCR( `PCRNUM` ).  
<br>  
<br>  

```
setmor DISABLEAUTODETECT
```

Sets Memory Overwrite Request (MOR) Bit. `DISABLEAUTODETECT` specifies if BIOS should auto detect unscheduled reboots.  
<br>  
<br>  

#### 2.6.2 Modified existing GRUB2 commands

* `linux` / `linux16`  
* `initrd` / `initrd16`  
* `chainloader`  
* `ntdlr`  

These commands are modified to measure before loading. PCR 14 is extended.

### 2.7 Other modifications

All modifications have been commented with

```C++
/* BEGIN TCG EXTENSION */

/* END TCG EXTENSION */
```

### 2.8 File list

The following list presents the files that have been added / modified to add TCG
support to GRUB2.

* README.md
* grub-core/Makefile.am
* grub-core/Makefile.core.def
* grub-core/boot/i386/pc/boot.S
* grub-core/boot/i386/pc/diskboot.S
* grub-core/kern/dl.c
* grub-core/kern/i386/pc/startup.S
* grub-core/kern/i386/pc/tpm/tpm.S
* grub-core/kern/i386/pc/tpm/tpm_kern.c
* grub-core/kern/sha1.c
* grub-core/disk/cryptodisk.c
* grub-core/disk/luks.c
* grub-core/loader/i386/linux.c
* grub-core/loader/i386/pc/chainloader.c
* grub-core/loader/i386/pc/linux.c
* grub-core/loader/i386/pc/ntldr.c
* grub-core/normal/main.c
* grub-core/script/execute.c
* grub-core/tpm/i386/pc/tpm.c
* include/grub/i386/pc/boot.h
* include/grub/i386/pc/tpm.h
* include/grub/sha1.h

## 3. Thanks

[TrustedGrub1](https://www.sirrix.com/content/pages/trustedgrub_en.htm) and GRUB-IMA have done a lot of preparatory work in the field and were used for code examples.
