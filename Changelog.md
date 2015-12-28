### Changelog

#### Not yet released

* 

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
