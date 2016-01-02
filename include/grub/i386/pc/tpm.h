/* Begin TCG extension */

/* i386-pc specific header file */

/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2014,2015  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_CPU_TPM_I386_PC_H
#define GRUB_CPU_TPM_I386_PC_H

#include <grub/types.h>
#include <grub/err.h>

/************************* constants *************************/

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

#define TCPA 0x41504354

/************************* macros *************************/

#define CHECK_FOR_NULL_ARGUMENT( argument ) 						                    \
			if( ! argument ) {										                    \
				grub_fatal( "BAD_ARGUMENT: argument is NULL" );   				\
			}

/************************* struct typedefs *************************/

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

/************************* functions *************************/

/* Invokes TCG_StatusCheck Int1A interrupt */
grub_err_t EXPORT_FUNC(grub_TPM_int1A_statusCheck)( grub_uint32_t* returnCode, grub_uint8_t* major, grub_uint8_t* minor,
		grub_uint32_t* featureFlags, grub_uint32_t* eventLog, grub_uint32_t* edi );

/* pass commands to TPM */
void EXPORT_FUNC(grub_TPM_int1A_passThroughToTPM) ( const PassThroughToTPM_InputParamBlock* input,
		PassThroughToTPM_OutputParamBlock* output );

#endif
/* End TCG Extension */
