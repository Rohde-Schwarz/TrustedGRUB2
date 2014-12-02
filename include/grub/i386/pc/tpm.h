/* Begin TCG extension */
#ifndef GRUB_CPU_TPM_KERN_H
#define GRUB_CPU_TPM_KERN_H

#include <grub/err.h>

/* #define TGRUB_DEBUG */

#ifdef TGRUB_DEBUG
	#define DEBUG_PRINT( x ) grub_printf x
#else
	#define DEBUG_PRINT( x )
#endif

#define CHECK_FOR_NULL_ARGUMENT( argument ) 						                    \
			if( ! argument ) {										                    \
				return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "argument is NULL" ) );   \
			}

#define SHA1_DIGEST_SIZE 20
#define TCPA 0x41504354

/* Measure into following PCRs */
#define TPM_LOADED_FILES_PCR 10
#define TPM_COMMAND_MEASUREMENT_PCR 11
#define TPM_LUKS_HEADER_MEASUREMENT_PCR 12

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

typedef struct {
	grub_uint32_t out_eax, out_ebx, out_ecx, out_edx, out_esi, out_edi;
} __attribute__ ((packed)) StatusCheckArgs;

typedef struct {
	grub_uint32_t out_eax;
	grub_uint32_t in_ebx, in_ecx, in_edx, in_esi, in_edi, in_es, in_ds;
} __attribute__ ((packed)) PassThroughToTPMArgs;

/* TCG_PassThroughToTPM Input Parameter Block */
typedef struct {
	grub_uint16_t IPBLength;
	grub_uint16_t Reserved1;
	grub_uint16_t OPBLength;
	grub_uint16_t Reserved2;
	grub_uint8_t TPMOperandIn[1];
} __attribute__ ((packed)) PassThroughToTPM_InputParamBlock;

/* TCG_PassThroughToTPM Output Parameter Block */
typedef struct {
	grub_uint16_t OPBLength;
	grub_uint16_t Reserved;
	grub_uint8_t TPMOperandOut[1];
} __attribute__ ((packed)) PassThroughToTPM_OutputParamBlock;

typedef struct {
	grub_uint32_t out_eax;
	grub_uint32_t in_ebx, in_ecx, in_edx, in_edi, in_es;
} __attribute__ ((packed)) SetMemoryOverwriteRequestBitArgs;

/* print SHA1 hash of input */
void EXPORT_FUNC(print_sha1) ( grub_uint8_t *inDigest );

/* 16 bit big to little-endian conversion */
grub_uint16_t EXPORT_FUNC(swap16) ( grub_uint16_t value );

/* 32 bit big to little-endian conversion */
grub_uint32_t EXPORT_FUNC(swap32) ( grub_uint32_t value );

/* 	Checks for TPM availability

  	Returns 1 if available
	Returns 0 if not
*/
grub_uint32_t EXPORT_FUNC(grub_TPM_isAvailable) ( void );

/* 	Measure string */
grub_err_t EXPORT_FUNC(grub_TPM_measureString) ( const char *string );
/* 	Measure file */
grub_err_t EXPORT_FUNC(grub_TPM_measureFile) ( const char* filename, const unsigned long index );
/* 	Measure buffer */
grub_err_t EXPORT_FUNC(grub_TPM_measureBuffer) ( const void* buffer, grub_uint32_t bufferLen, const unsigned long index );

/* Invokes assembler function asm_tcg_statusCheck() */
grub_err_t EXPORT_FUNC(tcg_statusCheck)( grub_uint32_t *returnCode, grub_uint8_t *major, grub_uint8_t *minor,
		grub_uint32_t *featureFlags, grub_uint32_t *eventLog, grub_uint32_t *edi );

/* pass commands to TPM */
grub_err_t EXPORT_FUNC(tcg_passThroughToTPM) ( const PassThroughToTPM_InputParamBlock* input,
		PassThroughToTPM_OutputParamBlock* output, grub_uint32_t* returnCode );

/* Assembler exports: */
grub_uint32_t EXPORT_FUNC(asm_tcg_statusCheck) (StatusCheckArgs* args);
grub_uint32_t EXPORT_FUNC(asm_tcg_passThroughToTPM) (PassThroughToTPMArgs* args);
grub_uint32_t EXPORT_FUNC(asm_tcg_SetMemoryOverwriteRequestBit) (SetMemoryOverwriteRequestBitArgs* args);

#endif
/* End TCG Extension */
