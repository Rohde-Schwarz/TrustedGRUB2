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

#include <grub/machine/tpm.h>
#include <grub/machine/memory.h>


/* Ordinals */
static const grub_uint32_t TPM_ORD_Extend = 0x00000014;

/* TPM_Extend Incoming Operand */
typedef struct {
	grub_uint16_t tag;
	grub_uint32_t paramSize;
	grub_uint32_t ordinal;
	grub_uint32_t pcrNum;
	grub_uint8_t inDigest[SHA1_DIGEST_SIZE];		/* The 160 bit value representing the event to be recorded. */
} __attribute__ ((packed)) ExtendIncoming;

/* TPM_Extend Outgoing Operand */
typedef struct {
	grub_uint16_t tag;
	grub_uint32_t paramSize;
	grub_uint32_t returnCode;
	grub_uint8_t outDigest[SHA1_DIGEST_SIZE];		/* The PCR value after execution of the command. */
} __attribute__ ((packed)) ExtendOutgoing;


/* ++++++++++++++++++++++++++++++++++++++++ */
/* code adapted from bitvisor http://www.bitvisor.org */
static void
conv32to16( grub_uint32_t src, grub_uint16_t *lowDest, grub_uint16_t *highDest ) {
	*lowDest = src;
	*highDest = src >> 16;
}

static void
conv16to32( grub_uint16_t lowSource, grub_uint16_t highSource, grub_uint32_t *dest ) {
	*dest = lowSource | (grub_uint32_t)highSource << 16;
}

static void
conv16to8( grub_uint16_t src, grub_uint8_t *lowDest, grub_uint8_t *highDest ) {
	*lowDest = src;
	*highDest = src >> 8;
}

static void
conv8to16( grub_uint8_t lowSource, grub_uint8_t highSource, grub_uint16_t *dest ) {
	*dest = lowSource | (grub_uint16_t)highSource << 8;
}

/* 16 bit big to little-endian conversion */
grub_uint16_t
swap16( grub_uint16_t value ) {
	grub_uint8_t low, high;

	conv16to8( value, &low, &high );
	conv8to16( high, low, &value );
	return value;
}

/* 32 bit big to little-endian conversion */
grub_uint32_t
swap32( grub_uint32_t value ) {
	grub_uint16_t low, high;

	conv32to16( value, &low, &high );
	conv16to32( swap16( high ), swap16( low ), &value );
	return value;
}
/* end functions from bitvisor */

void
print_sha1( grub_uint8_t *inDigest ) {

	/* print SHA1 hash of input */
	unsigned int j;
	for( j = 0; j < SHA1_DIGEST_SIZE; j++ ) {
		grub_printf( "%02x", inDigest[j] );
	}
}

/* Invokes assembler function asm_tcg_statusCheck()

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

	StatusCheckArgs args;

	/* invoke assembler func */
	asm_tcg_statusCheck( &args );

	*returnCode = args.out_eax;

	if( *returnCode != TCG_PC_OK ) {
		return grub_error( GRUB_ERR_TPM, N_( "tcg_statusCheck: asm_tcg_statusCheck failed: 0x%x" ), *returnCode );
	}

	if( args.out_ebx != TCPA ) {
        grub_fatal( "tcg_statusCheck: asm_tcg_statusCheck failed: args.out_ebx != TCPA" );
	}

	*major = (grub_uint8_t) (args.out_ecx >> 8);
	*minor = (grub_uint8_t) args.out_ecx;
	*featureFlags = args.out_edx;
	*eventLog = args.out_esi;
	*edi = args.out_edi;

	return GRUB_ERR_NONE;
}

/* Invokes assembler function asm_tcg_passThroughToTPM()

   grub_fatal() on error
   Page 112 TCG_PCClientImplementation_1-21_1_00
 */
void
tcg_passThroughToTPM( const PassThroughToTPM_InputParamBlock* input, PassThroughToTPM_OutputParamBlock* output ) {

	CHECK_FOR_NULL_ARGUMENT( input );
	CHECK_FOR_NULL_ARGUMENT( output );

    if( ! grub_TPM_isAvailable() ) {
    	grub_fatal( "tpm not available" );
    }

	if ( ! input->IPBLength || ! input->OPBLength ) {
        grub_fatal( "tcg_passThroughToTPM: ! input->IPBLength || ! input->OPBLength" );
	}

	/* copy input buffer */
	void* p = grub_map_memory( INPUT_PARAM_BLK_ADDR, input->IPBLength );

	grub_memcpy( p, input, input->IPBLength );

	grub_unmap_memory( p, input->IPBLength );

	PassThroughToTPMArgs args;
	args.in_ebx = TCPA;
	args.in_ecx = 0;
	args.in_edx = 0;
	args.in_esi = OUTPUT_PARAM_BLK_ADDR & 0xF;
	args.in_ds = OUTPUT_PARAM_BLK_ADDR >> 4;
	args.in_edi = INPUT_PARAM_BLK_ADDR & 0xF;
	args.in_es = INPUT_PARAM_BLK_ADDR >> 4;

	asm_tcg_passThroughToTPM( &args );

	if ( args.out_eax != TCG_PC_OK ) {
        grub_fatal( "tcg_passThroughToTPM: asm_tcg_passThroughToTPM failed: 0x%x", args.out_eax );
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

    if( ! grub_TPM_isAvailable() ) {
    	grub_fatal( "tpm not available" );
    }

	ExtendIncoming* extendInput;
	PassThroughToTPM_InputParamBlock* passThroughInput;
	grub_uint16_t inputlen = sizeof( *passThroughInput ) - sizeof( passThroughInput->TPMOperandIn ) + sizeof( *extendInput );

	ExtendOutgoing* extendOutput;
	PassThroughToTPM_OutputParamBlock* passThroughOutput;
	/* FIXME: Why are these additional +64 bytes needed? */
    grub_uint16_t outputlen = sizeof( *passThroughOutput ) - sizeof( passThroughOutput->TPMOperandOut ) + sizeof( *extendOutput ) + 64;

	passThroughInput = grub_zalloc( inputlen );
	if( ! passThroughInput ) {
        grub_fatal( "grub_TPM_measure: memory allocation failed" );
	}

	passThroughInput->IPBLength = inputlen;
	passThroughInput->OPBLength = outputlen;

	extendInput = (void *)passThroughInput->TPMOperandIn;
	extendInput->tag = swap16( TPM_TAG_RQU_COMMAND );
	extendInput->paramSize = swap32( sizeof( *extendInput ) );
	extendInput->ordinal = swap32( TPM_ORD_Extend );
	extendInput->pcrNum = swap32( (grub_uint32_t) index );

	grub_memcpy( extendInput->inDigest, inDigest, SHA1_DIGEST_SIZE);

	passThroughOutput = grub_zalloc( outputlen );
	if( ! passThroughOutput ) {
		grub_free( passThroughInput );
        grub_fatal( "grub_TPM_measure: memory allocation failed" );
	}

	tcg_passThroughToTPM( passThroughInput, passThroughOutput );
	grub_free( passThroughInput );

	extendOutput = (void *)passThroughOutput->TPMOperandOut;
	grub_uint32_t tpmExtendReturnCode = swap32( extendOutput->returnCode );

	if( tpmExtendReturnCode != TPM_SUCCESS ) {
		grub_free( passThroughOutput );

		if( tpmExtendReturnCode == TPM_BADINDEX ) {
            grub_fatal( "grub_TPM_measure: bad pcr index" );
		}
        grub_fatal( "grub_TPM_measure: tpmExtendReturnCode: %u", tpmExtendReturnCode );
	}

#ifdef TGRUB_DEBUG
	grub_printf( "New PCR[%lu]=", index );
	print_sha1( extendOutput->outDigest );
	grub_printf("\n\n");
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

	if( ! grub_TPM_isAvailable() ) {
		grub_fatal( "tpm not available" );
	}

	/* hash string */
	grub_uint32_t result[5];

	grub_err_t err = sha1_hash_string( string, result );

    if( err != GRUB_ERR_NONE ) {
		grub_fatal( "grub_TPM_measureString: sha1_hash_string failed." );
	}

	/* convert from uint32_t to uint8_t */
	grub_uint8_t convertedResult[SHA1_DIGEST_SIZE];
	int j, i = 0;
	for( j = 0; j < 5; j++ ) {
		convertedResult[i++] = ((result[j]>>24)&0xff);
		convertedResult[i++] = ((result[j]>>16)&0xff);
		convertedResult[i++] = ((result[j]>>8)&0xff);
		convertedResult[i++] = (result[j]&0xff);
	}

#ifdef TGRUB_DEBUG
    /* print SHA1 hash of input string */
    grub_printf( "\n" );
    print_sha1( convertedResult );
    grub_printf( "  %s\n", string );
#endif

	/* measure */
	grub_TPM_measure( convertedResult, TPM_COMMAND_MEASUREMENT_PCR );
}

/* grub_fatal() on error */
void
grub_TPM_measureFile( const char* filename, const unsigned long index ) {

	CHECK_FOR_NULL_ARGUMENT( filename )

	if( ! grub_TPM_isAvailable() ) {
		grub_fatal( "tpm not available." );
	}

	/* open file */
	grub_file_t file = grub_file_open( filename );
	if( ! file ) {
        grub_print_error();
        grub_fatal( "grub_TPM_measureFile: grub_file_open failed." );
	}

	/* hash file */
	grub_uint32_t result[5];
	grub_err_t err = sha1_hash_file( file, result  );

    if( err != GRUB_ERR_NONE ) {
		grub_fatal( "grub_TPM_measureFile: sha1_hash_file failed." );
	}

	grub_file_close( file );

    if ( grub_errno ) {
        grub_fatal( "grub_TPM_measureFile: grub_file_close failed." );
    }

	/* convert from uint32_t to uint8_t */
	grub_uint8_t convertedResult[SHA1_DIGEST_SIZE];
	int j, i = 0;
	for( j = 0; j < 5; j++ ) {
		convertedResult[i++] = ((result[j]>>24)&0xff);
		convertedResult[i++] = ((result[j]>>16)&0xff);
		convertedResult[i++] = ((result[j]>>8)&0xff);
		convertedResult[i++] = (result[j]&0xff);
	}

#ifdef TGRUB_DEBUG
    /* print hash */
    print_sha1( convertedResult );
#endif

	/* measure */
	grub_TPM_measure( convertedResult, index );
}

void
grub_TPM_measureBuffer( const void* buffer, const grub_uint32_t bufferLen, const unsigned long index ) {

	CHECK_FOR_NULL_ARGUMENT( buffer )

	if( ! grub_TPM_isAvailable() ) {
		grub_fatal( "tpm not available." );
	}

	/* hash buffer */
	grub_uint32_t result[5];
	grub_err_t err = sha1_hash_buffer( buffer, bufferLen, result );

    if( err != GRUB_ERR_NONE ) {
		grub_fatal( "grub_TPM_measureBuffer: sha1_hash_buffer failed." );
    }

	/* convert from uint32_t to uint8_t */
	grub_uint8_t convertedResult[SHA1_DIGEST_SIZE];
	int j, i = 0;
	for( j = 0; j < 5; j++ ) {
		convertedResult[i++] = ((result[j]>>24)&0xff);
		convertedResult[i++] = ((result[j]>>16)&0xff);
		convertedResult[i++] = ((result[j]>>8)&0xff);
		convertedResult[i++] = (result[j]&0xff);
	}

#ifdef TGRUB_DEBUG
    /* print hash */
    print_sha1( convertedResult );
#endif

	/* measure */
	grub_TPM_measure( convertedResult, index );
}
/* End TCG Extension */
