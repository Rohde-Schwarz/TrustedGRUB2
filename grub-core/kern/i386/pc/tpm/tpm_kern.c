/* Begin TCG Extension */

/* tpm_kern.c - tpm management */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2004,2005,2007,2008,2009  Free Software Foundation, Inc.
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

#include <grub/types.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/sha1.h>
#include <grub/misc.h>

#include <grub/machine/tpm.h>
#include <grub/machine/memory.h>
#include <grub/machine/int.h>


/* Ordinals */
static const grub_uint32_t TPM_ORD_Extend = 0x00000014;

/* TPM_Extend Incoming Operand */
typedef struct {
	grub_uint16_t tag;
	grub_uint32_t paramSize;
	grub_uint32_t ordinal;
	grub_uint32_t pcrNum;
	grub_uint8_t inDigest[SHA1_DIGEST_SIZE];		/* The 160 bit value representing the event to be recorded. */
} GRUB_PACKED ExtendIncoming;

/* TPM_Extend Outgoing Operand */
typedef struct {
	grub_uint16_t tag;
	grub_uint32_t paramSize;
	grub_uint32_t returnCode;
	grub_uint8_t outDigest[SHA1_DIGEST_SIZE];		/* The PCR value after execution of the command. */
} GRUB_PACKED ExtendOutgoing;


void
print_sha1( grub_uint8_t *inDigest ) {

	/* print SHA1 hash of input */
	unsigned int j;
	for( j = 0; j < SHA1_DIGEST_SIZE; j++ ) {
		grub_printf( "%02x", inDigest[j] );
	}
}

/* Invokes TCG_StatusCheck Int1A interrupt

   Returns:
   returnCode: int1A return codes
   major version
   minor version
   featureFlags
   eventLog
   edi

   For more information see page 115 TCG_PCClientImplementation 1.21

 */
grub_err_t
tcg_statusCheck( grub_uint32_t* returnCode, grub_uint8_t* major, grub_uint8_t* minor, grub_uint32_t* featureFlags, grub_uint32_t* eventLog, grub_uint32_t* edi ) {

	CHECK_FOR_NULL_ARGUMENT( returnCode )
	CHECK_FOR_NULL_ARGUMENT( major )
	CHECK_FOR_NULL_ARGUMENT( minor )
	CHECK_FOR_NULL_ARGUMENT( featureFlags )
	CHECK_FOR_NULL_ARGUMENT( eventLog )
	CHECK_FOR_NULL_ARGUMENT( edi )

	struct grub_bios_int_registers regs;
	regs.eax = 0xBB00;
	regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;

	/* invoke assembler func */
	grub_bios_interrupt (0x1A, &regs);

	*returnCode = regs.eax;

	if( *returnCode != TCG_PC_OK ) {
		grub_fatal( "TCG_StatusCheck failed: 0x%x", *returnCode );
	}

	if( regs.ebx != TCPA ) {
        grub_fatal( "TCG_StatusCheck failed: ebx != TCPA" );
	}

	*major = (grub_uint8_t) (regs.ecx >> 8);
	*minor = (grub_uint8_t) regs.ecx;
	*featureFlags = regs.edx;
	*eventLog = regs.esi;
	*edi = regs.edi;

	return GRUB_ERR_NONE;
}

/* Invokes assembler function TCG_PassThroughToTPM

   grub_fatal() on error
   Page 112 TCG_PCClientImplementation_1-21_1_00
 */
void
tcg_passThroughToTPM( const PassThroughToTPM_InputParamBlock* input, PassThroughToTPM_OutputParamBlock* output ) {

	CHECK_FOR_NULL_ARGUMENT( input );
	CHECK_FOR_NULL_ARGUMENT( output );

	if ( ! input->IPBLength || ! input->OPBLength ) {
        grub_fatal( "tcg_passThroughToTPM: ! input->IPBLength || ! input->OPBLength" );
	}

	/* copy input buffer */
	void* p = grub_map_memory( INPUT_PARAM_BLK_ADDR, input->IPBLength );

	grub_memcpy( p, input, input->IPBLength );

	grub_unmap_memory( p, input->IPBLength );

	struct grub_bios_int_registers regs;
	regs.eax = 0xBB02;
	regs.ebx = TCPA;
	regs.ecx = 0;
	regs.edx = 0;
	regs.esi = OUTPUT_PARAM_BLK_ADDR & 0xF;
	regs.ds = OUTPUT_PARAM_BLK_ADDR >> 4;
	regs.edi = INPUT_PARAM_BLK_ADDR & 0xF;
	regs.es = INPUT_PARAM_BLK_ADDR >> 4;
	regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;

	/* invoke assembler func */
	grub_bios_interrupt (0x1A, &regs);

	if ( regs.eax != TCG_PC_OK ) {
        grub_fatal( "TCG_PassThroughToTPM failed: 0x%x", regs.eax );
	}

	/* copy output_buffer */
	p = grub_map_memory( OUTPUT_PARAM_BLK_ADDR, input->OPBLength );

	grub_memcpy( output, p, input->OPBLength );

	grub_unmap_memory( p, input->OPBLength );

	/* FIXME:
	   output->OPBLength should be the same as input->OPBLength
	   But they are not ?!
	   output->Reserved has to be zero. But it is not. */
}

/* grub_fatal() on error */
static void
grub_TPM_measure( const grub_uint8_t* inDigest, const unsigned long index ) {

	CHECK_FOR_NULL_ARGUMENT( inDigest );

	ExtendIncoming* extendInput = NULL;
	PassThroughToTPM_InputParamBlock* passThroughInput = NULL;
	grub_uint16_t inputlen = sizeof( *passThroughInput ) - sizeof( passThroughInput->TPMOperandIn ) + sizeof( *extendInput );

	ExtendOutgoing* extendOutput = NULL;
	PassThroughToTPM_OutputParamBlock* passThroughOutput = NULL;
    grub_uint16_t outputlen = sizeof( *passThroughOutput ) - sizeof( passThroughOutput->TPMOperandOut ) + sizeof( *extendOutput );

	passThroughInput = grub_zalloc( inputlen );
	if( ! passThroughInput ) {
        grub_fatal( "grub_TPM_measure: memory allocation failed" );
	}

	passThroughInput->IPBLength = inputlen;
	passThroughInput->OPBLength = outputlen;

	extendInput = (void *)passThroughInput->TPMOperandIn;
	extendInput->tag = grub_swap_bytes16_compile_time( TPM_TAG_RQU_COMMAND );
	extendInput->paramSize = grub_swap_bytes32( sizeof( *extendInput ) );
	extendInput->ordinal = grub_swap_bytes32_compile_time( TPM_ORD_Extend );
	extendInput->pcrNum = grub_swap_bytes32( (grub_uint32_t) index );

	grub_memcpy( extendInput->inDigest, inDigest, SHA1_DIGEST_SIZE);

	passThroughOutput = grub_zalloc( outputlen );
	if( ! passThroughOutput ) {
		grub_free( passThroughInput );
        grub_fatal( "grub_TPM_measure: memory allocation failed" );
	}

	tcg_passThroughToTPM( passThroughInput, passThroughOutput );
	grub_free( passThroughInput );

	extendOutput = (void *)passThroughOutput->TPMOperandOut;
	grub_uint32_t tpmExtendReturnCode = grub_swap_bytes32( extendOutput->returnCode );

	if( tpmExtendReturnCode != TPM_SUCCESS ) {
		grub_free( passThroughOutput );

		if( tpmExtendReturnCode == TPM_BADINDEX ) {
            grub_fatal( "grub_TPM_measure: bad pcr index" );
		}
        grub_fatal( "grub_TPM_measure: tpmExtendReturnCode: %u", tpmExtendReturnCode );
	}

#ifdef TGRUB_DEBUG
	DEBUG_PRINT( ( "New PCR[%lu]=", index ) );
	print_sha1( extendOutput->outDigest );
	DEBUG_PRINT( ( "\n\n" ) );
#endif

	grub_free( passThroughOutput );
}

static unsigned int grubTPM_AvailabilityAlreadyChecked = 0;
static unsigned int grubTPM_isAvailable = 0;

/* Returns 1 if TPM is available, 0 otherwise . */
grub_uint32_t
grub_TPM_isAvailable( void ) {

	/* Checking for availability takes a while. so its useful to check this only once */
	if( grubTPM_AvailabilityAlreadyChecked ) {
		return grubTPM_isAvailable;
	}

	grub_uint32_t returnCode, featureFlags, eventLog, edi;
	grub_uint8_t major, minor;

	grub_err_t err = tcg_statusCheck( &returnCode, &major, &minor, &featureFlags, &eventLog, &edi );

    if( err == GRUB_ERR_NONE ) {
        grubTPM_isAvailable = 1;
    } else {
        grubTPM_isAvailable = 0;
        grub_errno = GRUB_ERR_NONE;
    }

	grubTPM_AvailabilityAlreadyChecked = 1;

	return grubTPM_isAvailable;
}

/* grub_fatal() on error */
void
grub_TPM_measureString( const char* string ) {

	CHECK_FOR_NULL_ARGUMENT( string )

	/* hash string */
	grub_uint32_t result[5] = { 0 };

	grub_err_t err = sha1_hash_string( string, result );

    if( err != GRUB_ERR_NONE ) {
		grub_fatal( "grub_TPM_measureString: sha1_hash_string failed." );
	}

	/* convert from uint32_t to uint8_t */
	grub_uint8_t convertedResult[SHA1_DIGEST_SIZE] = { 0 };
	int j, i = 0;
	for( j = 0; j < 5; j++ ) {
		convertedResult[i++] = ((result[j]>>24)&0xff);
		convertedResult[i++] = ((result[j]>>16)&0xff);
		convertedResult[i++] = ((result[j]>>8)&0xff);
		convertedResult[i++] = (result[j]&0xff);
	}

#ifdef TGRUB_DEBUG
    /* print SHA1 hash of input string */
	DEBUG_PRINT( ( "measured command: '%s'\n", string ) );
	DEBUG_PRINT( ( "SHA1: " ) );
    print_sha1( convertedResult );
    DEBUG_PRINT( ( "\n" ) );
#endif

	/* measure */
	grub_TPM_measure( convertedResult, TPM_COMMAND_MEASUREMENT_PCR );
}

/* grub_fatal() on error */
void
grub_TPM_measureFile( const char* filename, const unsigned long index ) {

	CHECK_FOR_NULL_ARGUMENT( filename )

	/* open file */
	grub_file_t file = grub_file_open( filename );
	if( ! file ) {
        grub_print_error();
        grub_fatal( "grub_TPM_measureFile: grub_file_open failed." );
	}

	/* hash file */
	grub_uint32_t result[5] = { 0 };
	grub_err_t err = sha1_hash_file( file, result  );

    if( err != GRUB_ERR_NONE ) {
		grub_fatal( "grub_TPM_measureFile: sha1_hash_file failed." );
	}

	grub_file_close( file );

    if ( grub_errno ) {
        grub_fatal( "grub_TPM_measureFile: grub_file_close failed." );
    }

	/* convert from uint32_t to uint8_t */
	grub_uint8_t convertedResult[SHA1_DIGEST_SIZE] = { 0 };
	int j, i = 0;
	for( j = 0; j < 5; j++ ) {
		convertedResult[i++] = ((result[j]>>24)&0xff);
		convertedResult[i++] = ((result[j]>>16)&0xff);
		convertedResult[i++] = ((result[j]>>8)&0xff);
		convertedResult[i++] = (result[j]&0xff);
	}

#ifdef TGRUB_DEBUG
    /* print hash */
	DEBUG_PRINT( ( "measured file: %s\n", filename ) );
	DEBUG_PRINT( ( "SHA1: " ) );
    print_sha1( convertedResult );
    DEBUG_PRINT( ( "\n" ) );
#endif

	/* measure */
	grub_TPM_measure( convertedResult, index );
}

void
grub_TPM_measureBuffer( const void* buffer, const grub_uint32_t bufferLen, const unsigned long index ) {

	CHECK_FOR_NULL_ARGUMENT( buffer )

	/* hash buffer */
	grub_uint32_t result[5] = { 0 };
	grub_err_t err = sha1_hash_buffer( buffer, bufferLen, result );

    if( err != GRUB_ERR_NONE ) {
		grub_fatal( "grub_TPM_measureBuffer: sha1_hash_buffer failed." );
    }

	/* convert from uint32_t to uint8_t */
	grub_uint8_t convertedResult[SHA1_DIGEST_SIZE] = { 0 };
	int j, i = 0;
	for( j = 0; j < 5; j++ ) {
		convertedResult[i++] = ((result[j]>>24)&0xff);
		convertedResult[i++] = ((result[j]>>16)&0xff);
		convertedResult[i++] = ((result[j]>>8)&0xff);
		convertedResult[i++] = (result[j]&0xff);
	}


#ifdef TGRUB_DEBUG
    /* print hash */
	DEBUG_PRINT( ( "SHA1: " ) );
    print_sha1( convertedResult );
    DEBUG_PRINT( ( "\n" ) );
#endif

	/* measure */
	grub_TPM_measure( convertedResult, index );
}
/* End TCG Extension */
