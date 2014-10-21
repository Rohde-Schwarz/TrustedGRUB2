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

   Return 0 on error.
   Return value = 1 if function successfully completed and TPM is available
   Further return values:
   returnCode: int1A return codes
   major version
   minor version
   featureFlags
   eventLog
   edi

   For more information see page 115 TCG_PCClientImplementation 1.21
 */
grub_uint32_t
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

	if( args.out_eax != TCG_PC_OK ) {
		DEBUG_PRINT( ( "args.out_eax != TCG_PC_OK\n" ) );
		return 0;
	}

	if( args.out_ebx != TCPA ) {
		DEBUG_PRINT( ( "args.out_ebx != TCPA\n" ) );
		return 0;
	}

	*major = (grub_uint8_t)(args.out_ecx >> 8);
	*minor = (grub_uint8_t)args.out_ecx;
	*featureFlags = args.out_edx;
	*eventLog = args.out_esi;
	*edi = args.out_edi;

	return 1;
}

/* Invokes assembler function asm_tcg_passThroughToTPM()

   Return 0 on error.
   Return value = 1 if function successfully completes
   On error see returncode;
   Page 112 TCG_PCClientImplementation_1-21_1_00
 */
grub_uint32_t
tcg_passThroughToTPM( const PassThroughToTPM_InputParamBlock* input, PassThroughToTPM_OutputParamBlock* output, grub_uint32_t* returnCode ) {

	CHECK_FOR_NULL_ARGUMENT( input );
	CHECK_FOR_NULL_ARGUMENT( output );

	if ( ! input->IPBLength || ! input->OPBLength ) {
		DEBUG_PRINT( ( "! input->IPBLength || ! input->OPBLength\n" ) );
		return 0;
	}

	/* copy input buffer */
	void* p = grub_map_memory( INPUT_PARAM_BLK_ADDR, input->IPBLength );

	if( ! p ) {
		return 0;
	}

	if( grub_memcpy( p, input, input->IPBLength ) != p ) {
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

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

	*returnCode = args.out_eax;

	if ( args.out_eax != TCG_PC_OK ) {
		DEBUG_PRINT( ( "args.out_eax != TCG_PC_OK\n" ) );
		return 0;
	}

	/* copy output_buffer */
	p = grub_map_memory( OUTPUT_PARAM_BLK_ADDR, input->OPBLength );

	if( !p ) {
		return 0;
	}

	if( grub_memcpy( output, p, input->OPBLength ) != output ) {
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	grub_unmap_memory( p, input->OPBLength );

	/* FIXME:
	   output->OPBLength should be the same as input->OPBLength
	   But they are not ?!
	   output->Reserved has to be zero. But it is not. */

	return 1;
}

static grub_uint32_t
grub_TPM_measure( const grub_uint8_t* inDigest, const unsigned long index ) {

	CHECK_FOR_NULL_ARGUMENT( inDigest );

	ExtendIncoming* extendInput;
	PassThroughToTPM_InputParamBlock* passThroughInput;
	grub_uint32_t inputlen = sizeof( *passThroughInput ) - sizeof( passThroughInput->TPMOperandIn ) + sizeof( *extendInput );

	ExtendOutgoing* extendOutput;
	PassThroughToTPM_OutputParamBlock* passThroughOutput;
	/* FIXME: Why are these additional +64 bytes needed? */
	grub_uint32_t outputlen = sizeof( *passThroughOutput ) - sizeof( passThroughOutput->TPMOperandOut ) + sizeof( *extendOutput ) + 64;

	passThroughInput = grub_zalloc( inputlen );
	if( ! passThroughInput ) {
		DEBUG_PRINT( ( "memory allocation failed.\n" ) );
		return 0 ;
	}

	passThroughInput->IPBLength = inputlen;
	passThroughInput->OPBLength = outputlen;

	extendInput = (void *)passThroughInput->TPMOperandIn;
	extendInput->tag = swap16( TPM_TAG_RQU_COMMAND );
	extendInput->paramSize = swap32( sizeof( *extendInput ) );
	extendInput->ordinal = swap32( TPM_ORD_Extend );
	extendInput->pcrNum = swap32( index );

	if( grub_memcpy( extendInput->inDigest, inDigest, SHA1_DIGEST_SIZE) != extendInput->inDigest ) {
		grub_free( passThroughInput );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	passThroughOutput = grub_zalloc( outputlen );
	if( ! passThroughOutput ) {
		grub_free( passThroughInput );
		DEBUG_PRINT( ( "memory allocation failed.\n" ) );
		return 0;
	}

	grub_uint32_t passThrough_TPM_ReturnCode;
	if ( tcg_passThroughToTPM( passThroughInput, passThroughOutput, &passThrough_TPM_ReturnCode ) == 0 ) {
		DEBUG_PRINT( ( "tcg_passThroughToTPM failed with: %x\n", passThrough_TPM_ReturnCode ) );
		grub_free( passThroughInput );
		grub_free( passThroughOutput );
		return 0;
	}
	grub_free( passThroughInput );

	extendOutput = (void *)passThroughOutput->TPMOperandOut;
	grub_uint32_t tpmExtendReturnCode = swap32( extendOutput->returnCode );

	if( tpmExtendReturnCode != TPM_SUCCESS ) {
		grub_free( passThroughOutput );

		if( tpmExtendReturnCode == TPM_BADINDEX ) {
			grub_printf( "Bad PCR index\n" );
			return 0;
		}
		return 0;
	}

#ifdef TGRUB_DEBUG
	grub_printf( "New PCR[%lu]=", index );
	print_sha1( extendOutput->outDigest );
	grub_printf("\n\n");
#endif

	grub_free( passThroughOutput );
	return 1;
}

static unsigned int grubTPM_AvailabilityAlreadyChecked = 0;
static unsigned int grubTPM_isAvailable = 0;

/* Returns 1 if TPM is available . */
grub_uint32_t
grub_TPM_isAvailable( void ) {

	/* Checking for availability takes a while. so its useful to check this only once */
	if( grubTPM_AvailabilityAlreadyChecked ) {
		return grubTPM_isAvailable;
	}

	grub_uint32_t returnCode, featureFlags, eventLog, edi;
	grub_uint8_t major, minor;

	if( tcg_statusCheck( &returnCode, &major, &minor, &featureFlags, &eventLog, &edi ) == 1 ) {
		grubTPM_isAvailable = 1;
	} else {
		grubTPM_isAvailable = 0;
	}

	grubTPM_AvailabilityAlreadyChecked = 1;

	return grubTPM_isAvailable;
}

/* Returns 0 on error. */
grub_uint32_t
grub_TPM_measureString( const char* string ) {

	CHECK_FOR_NULL_ARGUMENT( string )

	if( ! grub_TPM_isAvailable() ) {
		return 0;
	}

	/* hash string */
	grub_uint32_t result[5];

	if( sha1_hash_string( string, result ) == 0 ) {
		DEBUG_PRINT( ( "sha1_hash_string() failed\n" ) );
		return 0;
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
	if( grub_TPM_measure( convertedResult, TPM_COMMAND_MEASUREMENT_PCR ) == 0 ) {
		grub_printf( "Measurement failed\n" );
		return 0;
	}

	return 1;
}

/* Returns 0 on error. */
grub_uint32_t
grub_TPM_measureFile( const char* filename, const unsigned long index ) {

	CHECK_FOR_NULL_ARGUMENT( filename )

	if( ! grub_TPM_isAvailable() ) {
		return 0;
	}

	/* open file */
	grub_file_t file = grub_file_open( filename );
	if( ! file ) {
		grub_print_error();
		return 0;
	}

	/* hash file */
	grub_uint32_t result[5];
	if( sha1_hash_file( file, result  ) == 0)  {
		DEBUG_PRINT( ( "sha1_hash_file() failed" ) );
		return 0;
	}

	grub_file_close( file );

	if( grub_errno != GRUB_ERR_NONE ) {
		grub_print_error();
		return 0;
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
grub_printf( "  %s\n", filename );
#endif

	/* measure */
	if( grub_TPM_measure( convertedResult, index ) == 0 ) {
		DEBUG_PRINT( ( "grub_TPM_measure() failed\n" ) );
		return 0;
	}

	return 1;
}

/* End TCG Extension */
