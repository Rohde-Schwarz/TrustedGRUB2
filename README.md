# TrustedGRUB2

[![Build Status](https://travis-ci.org/Sirrix-AG/TrustedGRUB2.svg?branch=master)](https://travis-ci.org/Sirrix-AG/TrustedGRUB2)

<a href="https://scan.coverity.com/projects/5521">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/5521/badge.svg"/>
</a>

## 1. General Information

### 1.1 Introduction

This file describes the extensions made to transform a standard GRUB2 into a version that offers TCG (TPM) support for granting the integrity of the boot process (trusted boot). This project was highly inspired by the former projects [TrustedGrub1](https://www.sirrix.com/content/pages/trustedgrub_en.htm) and GRUB-IMA. However TrustedGRUB2 was completely written from scratch.

TrustedGRUB2 is measuring all critical components during the boot process, i.e. GRUB2 kernel, GRUB2 modules, the OS kernel or OS modules and so on, together with their
parameters. Please note that the TrustedGRUB2 MBR bootcode has not to be checked here (it wouldn't even be possible). The MBR bootcode has already been measured by the TPM itself.
Since the TPM is passive, it has no direct ability to check if the integrity of bootloader (and the OS kernel/modules and so on) actually is correct.
This can only be done indirectly by using the seal/unseal functions of the TPM (for details on this topic, you should have a look at the TCG specifications or on other documents describing TCG/TPM abilities).

### 1.2 Features

* Based on GRUB2 (master branch, last merge: 23.12.2015)
* TPM Support with TPM detection (only legacy/mbr mode, UEFI is not supported at the moment)
* Measurement of GRUB2 kernel
* Measurement of all loaded GRUB2 modules
* Measurement of all commands and their parameters entered in shell and scripts
* New SHA1-implementation in GRUB2 kernel (necessary for doing the GRUB2 modules measurement as the crypto module isn't loaded at this stage)
* Added LUKS keyfile support with additional parameter `-k KEYFILE` for `cryptomount` command
* Added support for unsealing LUKS keyfile with additional `-s` parameter for `cryptomount` command. LUKS-header is measured before unsealing into PCR 12. Currently unsealing only supported with SRK and well known secret (20 zero bytes)
* New commands:
  * `readpcr PCRNUM`
  * `tcglog LOGINDEX`
  * `measure FILE PCRNUM`
  * `setmor DISABLEAUTODETECT`
* Loader measurements:
  * `linux` / `linux16`
  * `initrd` / `initrd16`
  * `chainloader`
  * `ntdlr`
  * `multiboot`
  * `module`
* New cryptomount parameters:
  * `cryptomount -k KEYFILE`
  * `cryptomount -k KEYFILE -s`
* Functionality added without own command:
  * TPM_Unseal
  * TPM_GetRandom
  * TPM_OIAP
  * TPM_OSAP

### 1.3 Measurements (in short)

* PCR 0-7 Measured by BIOS
* PCR 8 First sector of TrustedGRUB2 kernel (diskboot.img)
* PCR 9 TrustedGRUB2 kernel (core.img)
* PCR 10 Loader measurements - currently linux-kernel, initrd, ntldr, chainloader, multiboot, module
* PCR 11 Contains all commandline arguments from scripts (e.g. grub.cfg) and those entered in the shell
* PCR 12 LUKS-header
* PCR 13 Parts of GRUB2 that are loaded from disk like GRUB2-modules // TODO: fonts, themes, locales

Kernel measurements are only implemented for diskboot so far (e.g. no cdboot or pxeboot measurement)

### 1.4 Requirements

In order to use the TCG-enhanced TrustedGRUB2, you need a computer which has TCG enhancements according to TCG specs. v1.2, since SHA1-calculations are extended into PC-Registers of the TPM.

### 1.5 Known Bugs / Limitations

* On some HP notebooks and workstations, TrustedGRUB2 (in default mode) is not able to do the kernel measurements due to a buggy BIOS. This means PCR 9 can 
contain bogus values. HP desktop/laptop BIOS seems to be unable to handle blocks ending on 512 byte boundaries when measuring data.
  * Fortunately we've found a workaround:
    * The workaround works as follows: we increase the number of bytes to read by 1 and also the number of sectors to read, which ensures that all 
bytes of core.img are read. For this to work correctly the loaded core.img must be padded with zeroes.
    * In summary: 
      1. pad core.img with zeroes to 512 byte blocks.
      2. append 1 extra zero byte to core.img.
    * This doesn't have to be done manually. We've patched `grub_mkimage` to do step 1 and step 2 for us.
    * This workaround has to be enabled explicitly. To do so: define `TGRUB_HP_WORKAROUND`. For example like this: `make 
CPPFLAGS=-DTGRUB_HP_WORKAROUND`
    * IMPORTANT: you have to append `--no-rs-codes` to `grub-install` otherwise you end up in a reboot loop.

If you find any other bugs, create an issue on github

### 1.6 Configuring TrustedGRUB2 before installation

#### 1.6.1 PCR selection
PCR selection for module measurement, command measurement and loaded files measurement can be adjusted in tpm.h:

```C++
#define TPM_LOADER_MEASUREMENT_PCR 10
#define TPM_COMMAND_MEASUREMENT_PCR 11
#define TPM_LUKS_HEADER_MEASUREMENT_PCR 12
#define TPM_GRUB2_LOADED_FILES_MEASUREMENT_PCR 13
```

#### 1.6.2 Debug output

To enable some debug output define `TGRUB_DEBUG`. For example like this `make CPPFLAGS=-DTGRUB_DEBUG`

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
./configure --prefix=INSTALLDIR --target=i386 -with-platform=pc
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

This chain of trust can be extended by using the newly added `measure` command to measure the integrity of arbitrary files.

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
Therefore the GRUB2 module loader was modified to measure modules to PCR 13 before they are loaded. Changes can be found in dl.c .

### 2.4 New SHA1-implementation in GRUB2 kernel

In order to make GRUB2 modules measurement possible, a SHA1-implementation had to be added to the kernel.
GRUB2 already contains an SHA1-implementation in its crypto module, but this isn't loaded at this stage.

### 2.5 Measurement of all commands and their parameters entered in shell and scripts

All commands which are entered in shell or executed by scripts is measured to PCR 11. Therefore commands in grub.cfg are automatically measured. No need to measure grub.cfg separately.
One exception applies to this rule: The `menuentry`, `submenu` and `[ ... ]` commands are not measured because it makes precomputation of the PCR 
value difficult and is unnecessary because each command within `menuentry` or `submenu` is anyway measured. For `[ ... ]` it shouldn't be possible to 
write commands between the square brackets.

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
* `multiboot`
* `module`
  * append `--nounzip` to get measuremens of the compressed file 

These commands are modified to measure before loading. PCR 10 is extended.

Additionally the following commands have been modified:

* `cryptomount`

### 2.7 Other modifications

All modifications have been commented with

```C++
/* BEGIN TCG EXTENSION */

/* END TCG EXTENSION */
```

### 2.8 Security considerations

* The `multiboot` command measurement does not follow the new convention of measuring the same buffer that is loaded into memory. If someone needs this extra security feel free to send a pull request. See GH #9 and GH #38 for more details.

### 2.9 File list

The following list presents the files that have been added / modified to add TCG
support to GRUB2.

* README.md
* Changelog.md
* grub-core/Makefile.am
* grub-core/Makefile.core.def
* grub-core/boot/i386/pc/boot.S
* grub-core/boot/i386/pc/diskboot.S
* grub-core/kern/tpm.c
* grub-core/kern/dl.c
* grub-core/kern/i386/pc/tpm/tpm_kern.c
* grub-core/kern/sha1.c
* grub-core/disk/cryptodisk.c
* grub-core/disk/luks.c
* grub-core/loader/multiboot.c
* grub-core/loader/linux.c
* grub-core/loader/i386/linux.c
* grub-core/loader/i386/pc/chainloader.c
* grub-core/loader/i386/pc/linux.c
* grub-core/loader/i386/pc/ntldr.c
* grub-core/normal/main.c
* grub-core/script/execute.c
* grub-core/tpm/i386/pc/tpm.c
* include/grub/i386/pc/boot.h
* include/grub/i386/pc/tpm.h
* include/grub/tpm.h
* include/grub/sha1.h
* util/mkimage.c

## 3. Thanks

[TrustedGrub1](https://www.sirrix.com/content/pages/trustedgrub_en.htm) and GRUB-IMA have done a lot of preparatory work in the field and were used for code examples.
