### Changelog

#### 1.5.0
* Update to GRUB 2.02

#### 1.4.0
* Extend log on each TPM_Extend GH #11

#### 1.3.0

* Fix measurement of compressed files. Previously the uncompressed version of the file was measured and not the one that is stored on the disk. GH #28
* Command measurement: in addition to not measuring `menuentry` also `submenu` and `[ ... ]` are not measured to simplify precomputation. GH #25
* Update to latest GRUB2 master (23.12.2015) that also includes a fix for CVE-2015-8370
* Prevent possible buffer overlow in case the command to measure is greater than 1024 byte in length
* Disable HP workaround in default mode, i.e. HP workaround has to be enabled explicitly by defining `TGRUB_HP_WORKAROUND`. Therefore there is no need to append `--no-rs-codes` to `grub-install` anymore in case you don't need the workaround. GH #18
* Measure buffer that is used. Before this fix everything that was measured from disk was read a second time. This enabled following attack: A sufficiently malicious storage device might provide a backdoored file on the first read attempt, followed by the correct file on the second read attempt. The measurement would then appear correct. GH #9
* Measurements of parts of TrustedGRUB2 that are loaded at runtime like grub2-modules are now seperated from the loader measurements like kernel and initrd. Additionally renamed `TPM_LOADED_FILES_PCR` to `TPM_LOADER_MEASUREMENT_PCR` and introduced a new define `TPM_GRUB2_LOADED_FILES_MEASUREMENT_PCR` for the GRUB2 measurements. GH #34
* Add multiboot measurements for `multiboot` and `module` commands. For now the `multiboot` measurement does not follow the new convention of measuring the same buffer that is loaded into memory. If someone needs this extra security feel free to send a pull request. GH #35

#### 1.2.1

* Implemented a workaround for buggy HP desktop/laptop BIOS. 
  * Measurement of PCR 8 / PCR 9 should be correct now on these devices.The way the core.img is created / measured has changed a bit. So resealing is necessary.
  * For the moment it is necessary to call `grub-install` with `--no-rs-codes`

#### 1.2.0

* sync with upstream GRUB2
* use build in byte swap functions instead of own
* improved debug output
* some general cleanup

#### 1.1.0

* fixed wrong parameter type sizes in grub_TPM_openOSAP_Session
* use grub_bios_interrupt() instead of self written assembler functions
* check if TPM is present but deactivated

#### 1.0.3

* fix out-of-bounds read in cryptomount command

#### 1.0.2

* abort boot process in case of errors during TrustedGRUB2 kernel measurement

#### 1.0.1

* treat errors in tpm functionality as fatal erros
* fixed bug in cryptomount command, if there is more than one keyslot

#### 1.0.0

* initial release
