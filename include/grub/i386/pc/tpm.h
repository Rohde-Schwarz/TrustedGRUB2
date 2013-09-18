/* Begin TCG extension */
#ifndef GRUB_CPU_TPM_H
#define GRUB_CPU_TPM_H

#include <grub/types.h>
#include <grub/symbol.h>

#define SHA1_DIGEST_SIZE 20
#define TCPA 0x41504354

/* int1A return codes */
#define TCG_PC_OK		0x0000
#define TCG_PC_TPMERROR(TPM_driver_error) \
	((TCG_PC_OK + 0x01) | ((TPM_driver_error) << 16))
#define TCG_PC_LOGOVERFLOW	(TCG_PC_OK + 0x02)
#define TCG_PC_UNSUPPORTED	(TCG_PC_OK + 0x03)

/* Command return codes */
#define TPM_BASE 0x0
#define TPM_SUCCESS TPM_BASE
#define TPM_BADINDEX (TPM_BASE + 0x2)

#define INPUT_PARAM_BLK_ADDR 0x10000
#define OUTPUT_PARAM_BLK_ADDR 0x20000

#define TPM_TAG_RQU_COMMAND 193
#define TPM_ORD_Extend 0x14
#define TPM_ORD_PcrRead 0x15

/*
  	typedef unsigned char grub_uint8_t;
	typedef unsigned short grub_uint16_t;
	typedef unsigned grub_uint32_t;

 */

/*
struct tcgbios_args {
	u32 out_eax, out_ebx, out_ecx, out_edx, out_esi, out_edi, out_ds;
	u32 in_ebx, in_ecx, in_edx, in_esi, in_edi, in_es, in_ds;
} __attribute__ ((packed));
*/

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
grub_uint32_t grub_TPM_isAvailable( void );

/* 	Measure string into PCR 12 */
grub_err_t grub_TPM_measureString( char *string );

/* Assembler exports: */
grub_uint32_t EXPORT_FUNC(asm_tcg_statusCheck) (struct tcg_statusCheck_args *args);
grub_uint32_t EXPORT_FUNC(asm_tcg_passThroughToTPM) (struct tcg_passThroughToTPM_args *args);


#endif /* GRUB_CPU_TPM_H */
/* End TCG extension */
