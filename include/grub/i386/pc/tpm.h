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
				grub_fatal( "BAD_ARGUMENT: argument is NULL" );   				\
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

/* TCG_PassThroughToTPM Input Parameter Block */
typedef struct {
	grub_uint16_t IPBLength;
	grub_uint16_t Reserved1;
	grub_uint16_t OPBLength;
	grub_uint16_t Reserved2;
	grub_uint8_t TPMOperandIn[1];
} GRUB_PACKED PassThroughToTPM_InputParamBlock;

/* TCG_PassThroughToTPM Output Parameter Block */
typedef struct {
	grub_uint16_t OPBLength;
	grub_uint16_t Reserved;
	grub_uint8_t TPMOperandOut[1];
} GRUB_PACKED PassThroughToTPM_OutputParamBlock;

/* print SHA1 hash of input */
void EXPORT_FUNC(print_sha1) ( grub_uint8_t* inDigest );

/* 	Checks for TPM availability
	Returns 1 if available
	Returns 0 if not
*/
grub_uint32_t EXPORT_FUNC(grub_TPM_isAvailable) ( void );

/* 	Measure string */
void EXPORT_FUNC(grub_TPM_measureString) ( const char* string );
/* 	Measure file */
void EXPORT_FUNC(grub_TPM_measureFile) ( const char* filename, const unsigned long index );
/* 	Measure buffer */
void EXPORT_FUNC(grub_TPM_measureBuffer) ( const void* buffer, grub_uint32_t bufferLen, const unsigned long index );

void grub_TPM_unseal( const grub_uint8_t* sealedBuffer, const grub_size_t inputSize, grub_uint8_t** result, grub_size_t* resultSize );

/* Invokes TCG_StatusCheck Int1A interrupt */
grub_err_t EXPORT_FUNC(tcg_statusCheck)( grub_uint32_t* returnCode, grub_uint8_t* major, grub_uint8_t* minor,
		grub_uint32_t* featureFlags, grub_uint32_t* eventLog, grub_uint32_t* edi );

/* pass commands to TPM */
void EXPORT_FUNC(tcg_passThroughToTPM) ( const PassThroughToTPM_InputParamBlock* input,
		PassThroughToTPM_OutputParamBlock* output );

#endif
/* End TCG Extension */
