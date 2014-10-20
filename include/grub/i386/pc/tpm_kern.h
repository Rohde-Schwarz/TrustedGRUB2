/* Begin TCG extension */
#ifndef GRUB_CPU_TPM_KERN_H
#define GRUB_CPU_TPM_KERN_H

#include <grub/err.h>

#define TGRUB_DEBUG

#ifdef TGRUB_DEBUG
	#define DEBUG_PRINT( x ) grub_printf x
#else
	#define DEBUG_PRINT( x )
#endif

#define SHA1_DIGEST_SIZE 20
#define TPM_NONCE_SIZE 20
#define TPM_AUTHDATA_SIZE 20

#define TCPA 0x41504354

/* Measure into following PCRs */
#define TPM_GRUB_LOADED_MODULES_PCR 11
#define TPM_COMMAND_MEASUREMENT_PCR 12
#define TPM_LOADED_FILES_PCR 14

/* int1A return codes */
#define TCG_PC_OK		0x0000
#define TCG_PC_TPMERROR(TPM_driver_error) \
	((TCG_PC_OK + 0x01) | ((TPM_driver_error) << 16))
#define TCG_PC_LOGOVERFLOW	(TCG_PC_OK + 0x02)
#define TCG_PC_UNSUPPORTED	(TCG_PC_OK + 0x03)

/* Command return codes */
#define TPM_BASE 0x0
#define TPM_SUCCESS TPM_BASE
#define TPM_AUTHFAIL (TPM_BASE + 0x1)
#define TPM_BADINDEX (TPM_BASE + 0x2)


/* TODO: 0x10000 does not work for some reason */
/* is  0x20000 and 0x30000 a good choice? */
#define INPUT_PARAM_BLK_ADDR 0x30000
#define OUTPUT_PARAM_BLK_ADDR 0x20000

#define TPM_TAG_RQU_COMMAND 0x00C1
#define TPM_TAG_RQU_AUTH2_COMMAND 0x00C3

/* Ordinals */
#define TPM_ORD_Extend 0x14
#define TPM_ORD_PcrRead 0x15
#define TPM_ORD_Unseal 0x18
#define TPM_ORD_GetRandom 0x46
#define TPM_ORD_OIAP 0xA

/* Key Handle Values */
#define TPM_KH_SRK 0x40000000

struct tcg_statusCheck_args {
	grub_uint32_t out_eax, out_ebx, out_ecx, out_edx, out_esi, out_edi;
} __attribute__ ((packed));

struct tcg_passThroughToTPM_args {
	grub_uint32_t out_eax;
	grub_uint32_t in_ebx, in_ecx, in_edx, in_esi, in_edi, in_es, in_ds;
} __attribute__ ((packed));

/* TCG_PassThroughToTPM Input Parameter Block */
struct tcg_passThroughToTPM_InputParamBlock {
	grub_uint16_t IPBLength;
	grub_uint16_t Reserved1;
	grub_uint16_t OPBLength;
	grub_uint16_t Reserved2;
	grub_uint8_t TPMOperandIn[1];
} __attribute__ ((packed));

/* TCG_PassThroughToTPM Output Parameter Block */
struct tcg_passThroughToTPM_OutputParamBlock {
	grub_uint16_t OPBLength;
	grub_uint16_t Reserved;
	grub_uint8_t TPMOperandOut[1];
} __attribute__ ((packed));

struct tcg_SetMemoryOverwriteRequestBit_args {
	grub_uint32_t out_eax;
	grub_uint32_t in_ebx, in_ecx, in_edx, in_edi, in_es;
} __attribute__ ((packed));

/* TCG_SetMemoryOverwriteRequestBit Input Parameter Block */
struct tcg_SetMemoryOverwriteRequestBit_InputParamBlock {
	grub_uint16_t iPBLength;
	grub_uint16_t reserved;
	grub_uint8_t  memoryOverwriteAction_BitValue;
} __attribute__ ((packed));

typedef struct tdTCG_PCClientPCREventStruc {
	grub_uint32_t pcrIndex;
	grub_uint32_t eventType;
	grub_uint8_t digest[SHA1_DIGEST_SIZE];
	grub_uint32_t eventDataSize;
	grub_uint8_t event[1];
} __attribute__ ((packed)) TCG_PCClientPCREvent;
#define TCG_PCR_EVENT_SIZE 32



/* 	Checks for TPM availability

  	Returns 1 if available
	Returns 0 if not
*/
grub_uint32_t EXPORT_FUNC(grub_TPM_isAvailable) ( void );

/* 	Measure string */
grub_uint32_t EXPORT_FUNC(grub_TPM_measureString) ( char *string );
/* 	Measure files */
grub_uint32_t EXPORT_FUNC(grub_TPM_measureFile) ( const char* filename, const unsigned long index );

/* read pcr specified by index */
/*TODO: print in cmd function. here: return result in second parameter  */
grub_uint32_t EXPORT_FUNC(grub_TPM_readpcr) ( unsigned long index );

/* read tcg log entry specified by index */
grub_uint32_t EXPORT_FUNC(grub_TPM_read_tcglog) ( int index );

/* Unseals file with SRK */
//grub_uint32_t EXPORT_FUNC(grub_TPM_unseal) ( const char* sealedFile );

/* get random from TPM  */
grub_uint32_t EXPORT_FUNC(grub_TPM_getRandom) ( unsigned char* random, const grub_uint32_t randomBytesRequested );

/* get random from TPM  */
grub_uint32_t EXPORT_FUNC(grub_TPM_openOIAP_Session) ( grub_uint32_t* authHandle, unsigned char* nonceEven );

/* Assembler exports: */
grub_uint32_t EXPORT_FUNC(asm_tcg_statusCheck) (struct tcg_statusCheck_args *args);
grub_uint32_t EXPORT_FUNC(asm_tcg_passThroughToTPM) (struct tcg_passThroughToTPM_args *args);
grub_uint32_t EXPORT_FUNC(asm_tcg_SetMemoryOverwriteRequestBit) (struct tcg_SetMemoryOverwriteRequestBit_args *args);

#endif
/* End TCG Extension */
