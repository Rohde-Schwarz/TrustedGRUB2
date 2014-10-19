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

#include <grub/machine/tpm_kern.h>
#include <grub/machine/memory.h>

static void
print_sha1( grub_uint8_t *inDigest ) {

	/* print SHA1 hash of input file */
	unsigned int j;
	for( j = 0; j < SHA1_DIGEST_SIZE; j++ ) {
		grub_printf( "%02x", inDigest[j] );
	}
}
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
static grub_uint16_t
swap16( grub_uint16_t value ) {
	grub_uint8_t low, high;

	conv16to8( value, &low, &high );
	conv8to16( high, low, &value );
	return value;
}

/* 32 bit big to little-endian conversion */
static grub_uint32_t
swap32( grub_uint32_t value ) {
	grub_uint16_t low, high;

	conv32to16( value, &low, &high );
	conv16to32( swap16( high ), swap16( low ), &value );
	return value;
}
/* end functions from bitvisor */
/* ++++++++++++++++++++++++++++++++++++++++ */

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
static grub_uint32_t
tcg_statusCheck( grub_uint32_t *returnCode, grub_uint8_t *major, grub_uint8_t *minor, grub_uint32_t *featureFlags, grub_uint32_t *eventLog, grub_uint32_t *edi ) {
	struct tcg_statusCheck_args args;

	/* invoke assembler func */
	asm_tcg_statusCheck( &args );

	*returnCode = args.out_eax;

	if( args.out_eax != TCG_PC_OK ) {
		return 0;
	}

	if( args.out_ebx != TCPA ) {
		return 0;
	}

	*major = (grub_uint8_t)(args.out_ecx >> 8);
	*minor = (grub_uint8_t)args.out_ecx;
	*featureFlags = args.out_edx;
	*eventLog = args.out_esi;
	*edi = args.out_edi;

	/* grub_printf("%u", *major);
	   grub_printf(".%u", *minor); */
	return 1;
}

/* Invokes assembler function asm_tcg_passThroughToTPM()

   Return 0 on error.
   Return value = 1 if function successfully completes
   On error see returncode;
   Page 112 TCG_PCClientImplementation_1-21_1_00
 */
static grub_uint32_t
tcg_passThroughToTPM( struct tcg_passThroughToTPM_InputParamBlock *input,
				 	  struct tcg_passThroughToTPM_OutputParamBlock *output, grub_uint32_t *returnCode ) {

	struct tcg_passThroughToTPM_args args;
	void *p;

	if ( !input->IPBLength || !input->OPBLength ) {
		return 0;
	}

	/* copy input buffer */
	p = grub_map_memory( INPUT_PARAM_BLK_ADDR, input->IPBLength );
	if( !p ) {
		return 0;
	}
	if( grub_memcpy( p, input, input->IPBLength ) != p ) {
		return 0;
	}
	grub_unmap_memory( p, input->IPBLength );

	/*  grub_printf( "input->IPBLength: %x\n", input->IPBLength );
		grub_printf( "input->OPBLength: %x\n", input->OPBLength );
		grub_printf( "input->Reserved1: %x\n", input->Reserved1 );
		grub_printf( "input->Reserved2: %x\n", input->Reserved2 );
		grub_printf( "input->TPMOperandIn: %x\n", *input->TPMOperandIn ); */

	/* TPM_Extend Incoming Operand
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t ordinal;
		grub_uint32_t pcrNum;
		grub_uint8_t inDigest[SHA1_DIGEST_SIZE];
	} __attribute__ ((packed)) *tpmInput; */

	/* tpmInput = (void *)input->TPMOperandIn;
		grub_printf( "tpminput->tag: %x\n", tpmInput->tag );
		grub_printf( "tpminput->paramSize: %x\n", tpmInput->paramSize );
		grub_printf( "tpminput->ordinal: %x\n", tpmInput->ordinal );
		grub_printf( "tpminput->pcrNum: %x\n", tpmInput->pcrNum ); */

	args.in_ebx = TCPA;
	args.in_ecx = 0;
	args.in_edx = 0;
	args.in_esi = OUTPUT_PARAM_BLK_ADDR & 0xF;
	args.in_ds = OUTPUT_PARAM_BLK_ADDR >> 4;
	args.in_edi = INPUT_PARAM_BLK_ADDR & 0xF;
	args.in_es = INPUT_PARAM_BLK_ADDR >> 4;

	/* 	grub_printf( "esi: %x\n", args.in_esi );
		grub_printf( "ds: %x\n", args.in_ds );
		grub_printf( "edi: %x\n", args.in_edi );
		grub_printf( "es: %x\n", args.in_es ); */

	asm_tcg_passThroughToTPM( &args );

	*returnCode = args.out_eax;
	/* grub_printf( "%x\n", args.out_eax ); */

	if ( args.out_eax != TCG_PC_OK ) {
		return 0;
	}

	/* copy output_buffer */
	p = grub_map_memory( OUTPUT_PARAM_BLK_ADDR, input->OPBLength );
	if( !p ) {
		return 0;
	}
	if( grub_memcpy( output, p, input->OPBLength ) != output ) {
		return 0;
	}
	grub_unmap_memory( p, input->OPBLength );

	/* FIXME
	   output->OPBLength should be the same as input->OPBLength
	   But they are not ?!
	   output->Reserved has to be zero. But it is not. */

	/* grub_printf( "%x\n", output->OPBLength ); */
	/* grub_printf( "%x\n", output->Reserved ); */
	return 1;
}

/* Invokes assembler function asm_tcg_SetMemoryOverwriteRequestBit()

   Return 0 on error.
   Return value = 1 if function successfully completes
   On error see returncode;
   Page 12 TCG Platform Reset Attack Mitigation Specification V 1.0.0
 */
static grub_uint32_t
tcg_SetMemoryOverwriteRequestBit( struct tcg_SetMemoryOverwriteRequestBit_InputParamBlock *input ) {

	struct tcg_SetMemoryOverwriteRequestBit_args args;
	void *p;

	if ( !input->iPBLength ) {
		return 0;
	}

	/* copy input buffer */
	p = grub_map_memory( INPUT_PARAM_BLK_ADDR, input->iPBLength );
	if( !p ) {
		return 0;
	}
	if( grub_memcpy( p, input, input->iPBLength ) != p ) {
		return 0;
	}
	grub_unmap_memory( p, input->iPBLength );

	args.in_ebx = TCPA;
	args.in_ecx = 0;
	args.in_edx = 0;
	args.in_edi = INPUT_PARAM_BLK_ADDR & 0xF;
	args.in_es  = INPUT_PARAM_BLK_ADDR >> 4;

	asm_tcg_SetMemoryOverwriteRequestBit( &args );

	if ( args.out_eax != TCG_PC_OK ) {
		return 0;
	}

	return 1;
}

static grub_uint32_t
grub_TPM_measure( grub_uint8_t *inDigest, unsigned long index ) {

	/* TPM_Extend Incoming Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t ordinal;
		grub_uint32_t pcrNum;
		grub_uint8_t inDigest[SHA1_DIGEST_SIZE];		/* The 160 bit value representing the event to be recorded. */
	} __attribute__ ((packed)) *tpmInput;

	/* TPM_Extend Outgoing Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t returnCode;
		grub_uint8_t outDigest[SHA1_DIGEST_SIZE];		/* The PCR value after execution of the command. */
	} __attribute__ ((packed)) *tpmOutput;

	struct tcg_passThroughToTPM_InputParamBlock *input;
	struct tcg_passThroughToTPM_OutputParamBlock *output;

	grub_uint32_t inputlen = sizeof( *input ) - sizeof( input->TPMOperandIn ) + sizeof( *tpmInput );

	/* FIXME: Why is this Offset value (+64) needed? */
	grub_uint32_t outputlen = sizeof( *output ) - sizeof( output->TPMOperandOut ) + sizeof( *tpmOutput ) + 64 ;

	input = grub_zalloc( inputlen );
	if( !input ) {
		return 0 ;
	}
	output = grub_zalloc( outputlen );
	if( !output ) {
		return 0;
	}
	input->IPBLength = inputlen;
	input->OPBLength = outputlen;

	tpmInput = (void *)input->TPMOperandIn;
	tpmInput->tag = swap16( TPM_TAG_RQU_COMMAND );
	tpmInput->paramSize = swap32( sizeof( *tpmInput ) );
	tpmInput->ordinal = swap32( TPM_ORD_Extend );
	tpmInput->pcrNum = swap32( index );

	if( grub_memcpy( tpmInput->inDigest, inDigest, SHA1_DIGEST_SIZE) != tpmInput->inDigest ) {
		return 0;
	}

	grub_uint32_t passThrough_TPM_ReturnCode;
	if ( tcg_passThroughToTPM( input, output, &passThrough_TPM_ReturnCode ) == 0 ) {
		grub_free( input );
		grub_free( output );
		return 0;
	}

	tpmOutput = (void *)output->TPMOperandOut;
	grub_uint32_t tpmExtendReturnCode = swap32( tpmOutput->returnCode );

	if( tpmExtendReturnCode != TPM_SUCCESS ) {
		grub_free( input );
		grub_free( output );

		if( tpmExtendReturnCode == TPM_BADINDEX ) {
			grub_printf( "Bad PCR index\n" );
			return 0;
		}
		return 0;
	}

	grub_free( input );
	grub_free( output );

#ifdef TGRUB_DEBUG
	grub_printf( "New PCR[%lu]=", index );
	print_sha1( tpmOutput->outDigest );
	grub_printf("\n\n");
#endif

	return 1;
}

/* Sets Memory Overwrite Request bit */
/* Returns 0 on error */
grub_uint32_t
grub_TPM_SetMOR_Bit( unsigned int disableAutoDetect ) {

	struct tcg_SetMemoryOverwriteRequestBit_InputParamBlock input;
	input.iPBLength = 5;
	input.reserved = 0;

	// Reserved disableAutoDetect Reserved MOR-Bit
	// 000             0            000      0

	if( disableAutoDetect ) {
		// disable autodetect
		// 000 1 000 1
		input.memoryOverwriteAction_BitValue = 0x11;
	} else{
		// autodetect
		// 000 0 000 1
		input.memoryOverwriteAction_BitValue = 0x01;
	}

	if ( tcg_SetMemoryOverwriteRequestBit( &input ) == 0 ) {
		return 0;
	}

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
grub_TPM_measureString( char *string ) {

	if( grub_TPM_isAvailable() ) {
		if ( string == 0 ) {
			return 0;
		}

		/* hash string */
		grub_uint32_t result[5];

		if( sha1_hash_string( string, result ) == 0 ) {
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

	} else {
		return 0;
	}
	return 1;
}

/* Returns 0 on error. */
grub_uint32_t
grub_TPM_measureFile( const char* filename, const unsigned long index ) {

	if( grub_TPM_isAvailable() ) {
		if ( filename == 0 ) {
			return 0;
		}

		/* open file */
		grub_file_t file = grub_file_open( filename );
		if( !file ) {
			grub_print_error();
			return 0;
		}

		/* hash file */
		grub_uint32_t result[5];
		if( sha1_hash_file( file, result  ) == 0)  {
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
			grub_printf( "Measurement failed\n" );
			return 0;
		}

	} else {
	}

	return 1;
}

/* Returns 0 on error. */
grub_err_t
grub_TPM_readpcr( unsigned long index ) {

	if( grub_TPM_isAvailable() ) {
		struct tcg_passThroughToTPM_InputParamBlock *input;
		struct tcg_passThroughToTPM_OutputParamBlock *output;

		/* TPM_PCRRead Incoming Operand */
		struct {
			grub_uint16_t tag;
			grub_uint32_t paramSize;
			grub_uint32_t ordinal;
			grub_uint32_t pcrIndex;
		} __attribute__ ((packed)) *tpmInput;

		/* TPM_PCRRead Outgoing Operand */
		struct {
			grub_uint16_t tag;
			grub_uint32_t paramSize;
			grub_uint32_t returnCode;
			grub_uint8_t pcr_value[SHA1_DIGEST_SIZE];
		} __attribute__ ((packed)) *tpmOutput;

		grub_uint32_t inputlen = sizeof( *input ) - sizeof( input->TPMOperandIn ) + sizeof( *tpmInput );

		/* FIXME: Why is this Offset value (+47) needed? */
		grub_uint32_t outputlen = sizeof( *output ) - sizeof( output->TPMOperandOut ) + sizeof( *tpmOutput ) + 47 ;

		/* 	grub_printf( "output=%x ", sizeof( *output )  );
			grub_printf( "output->TPMOperandOut=%x ", sizeof( output->TPMOperandOut )  );
			grub_printf( "tpmOutput=%x ", sizeof( *tpmOutput )  );
			grub_printf( "tpmOutput->pcr_value=%x ", sizeof( tpmOutput->pcr_value )  ); */

		input = grub_zalloc( inputlen );
		if( !input ) {
			return 0;
		}

		output = grub_zalloc( outputlen );
		if( !output ) {
			return 0;
		}

		input->IPBLength = inputlen;
		input->OPBLength = outputlen;

		tpmInput = (void *)input->TPMOperandIn;
		tpmInput->tag = swap16( TPM_TAG_RQU_COMMAND );
		tpmInput->paramSize = swap32( sizeof( *tpmInput ) );
		tpmInput->ordinal = swap32( TPM_ORD_PcrRead );
		tpmInput->pcrIndex = swap32( index );

		grub_uint32_t passThroughTo_TPM_ReturnCode;
		if( tcg_passThroughToTPM( input, output, &passThroughTo_TPM_ReturnCode ) == 0 ) {
			grub_free( input );
			grub_free( output );
			return 0;
		}

		tpmOutput = (void *)output->TPMOperandOut;
		grub_uint32_t tpm_PCRreadReturnCode = swap32( tpmOutput->returnCode );

		if( tpm_PCRreadReturnCode != TPM_SUCCESS ) {
			grub_free( input );
			grub_free( output );

			if( tpm_PCRreadReturnCode == TPM_BADINDEX ) {
				grub_printf( "Bad PCR index\n" );
				return 0;
			}
			return 0;
		}

		grub_free( input );
		grub_free( output );

		grub_printf( "PCR[%lu]=", index );
		print_sha1( tpmOutput->pcr_value );
		grub_printf("\n");
	} else {
		return 0;
	}

	return 1;
}

/* Returns 0 on error. */
grub_err_t
grub_TPM_getRandom( unsigned char* random, const grub_uint32_t randomBytesRequested ) {

	if( ! grub_TPM_isAvailable() ) {
		return 0;
	}

	if( ! random )
	{
		DEBUG_PRINT( ( "random argument is NULL.\n" ) );
		return 0;
	}

	if( ! randomBytesRequested )
	{
		DEBUG_PRINT( ( "randomBytesRequested argument is 0.\n" ) );
		return 0;
	}

	/* TPM_GetRandom Incoming Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t ordinal;
		grub_uint32_t bytesRequested;
	} __attribute__ ((packed)) *tpmInput;

	/* TPM_GetRandom Outgoing Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t returnCode;
		grub_uint32_t randomBytesSize;
		grub_uint8_t  randomBytes[randomBytesRequested];
	} __attribute__ ((packed)) *tpmOutput;

	struct tcg_passThroughToTPM_InputParamBlock* input;
	grub_uint32_t inputlen = sizeof( *input ) - sizeof( input->TPMOperandIn ) + sizeof( *tpmInput );

	/* FIXME: Why is this Offset value (+47) needed? */
	struct tcg_passThroughToTPM_OutputParamBlock* output;
	grub_uint32_t outputlen = sizeof( *output ) - sizeof( output->TPMOperandOut ) + sizeof( *tpmOutput ) + 47 ;

	/* 	grub_printf( "output=%x ", sizeof( *output )  );
		grub_printf( "output->TPMOperandOut=%x ", sizeof( output->TPMOperandOut )  );
		grub_printf( "tpmOutput=%x ", sizeof( *tpmOutput )  );
		grub_printf( "tpmOutput->pcr_value=%x ", sizeof( tpmOutput->pcr_value )  ); */

	input = grub_zalloc( inputlen );
	if( ! input ) {
		DEBUG_PRINT( ( "memory allocation for 'input' failed\n" ) );
		return 0;
	}

	output = grub_zalloc( outputlen );
	if( ! output ) {
		DEBUG_PRINT( ( "memory allocation for 'output' failed\n" ) );
		return 0;
	}

	input->IPBLength = inputlen;
	input->OPBLength = outputlen;

	tpmInput = (void *)input->TPMOperandIn;
	tpmInput->tag = swap16( TPM_TAG_RQU_COMMAND );
	tpmInput->paramSize = swap32( sizeof( *tpmInput ) );
	tpmInput->ordinal = swap32( TPM_ORD_GetRandom );
	tpmInput->bytesRequested = swap32( randomBytesRequested );

	grub_uint32_t passThroughTo_TPM_ReturnCode;
	if( tcg_passThroughToTPM( input, output, &passThroughTo_TPM_ReturnCode ) == 0 ) {
		grub_free( input );
		grub_free( output );

		DEBUG_PRINT( ( "tcg_passThroughToTPM failed\n" ) );
		return 0;
	}

	tpmOutput = (void *)output->TPMOperandOut;
	grub_uint32_t tpm_getRandomReturnCode = swap32( tpmOutput->returnCode );

	if( tpm_getRandomReturnCode != TPM_SUCCESS ) {
		grub_free( input );
		grub_free( output );

		DEBUG_PRINT( ( "tpm_getRandomReturnCode: %x \n", tpm_getRandomReturnCode ) );
		return 0;
	}

	grub_free( input );
	grub_free( output );

	if( swap32( tpmOutput->randomBytesSize ) != randomBytesRequested ) {
		DEBUG_PRINT( ( "tpmOutput->randomBytesSize != randomBytesRequested\n" ) );
		DEBUG_PRINT( ( "tpmOutput->randomBytesSize = %x \n", swap32( tpmOutput->randomBytesSize ) ) );
		DEBUG_PRINT( ( "randomBytesRequested = %x \n", randomBytesRequested ) );
		return 0;
	}

	grub_memcpy( random, tpmOutput->randomBytes, randomBytesRequested );

	return 1;
}


/* Returns 0 on error. */
/* index = 0 for all entries */
grub_err_t
grub_TPM_read_tcglog( int index ) {

	if( grub_TPM_isAvailable() ) {
		grub_uint32_t returnCode, featureFlags, eventLog = 0, logAddr = 0, edi = 0;
		grub_uint8_t major, minor;

		/* get event log pointer */
		if( tcg_statusCheck( &returnCode, &major, &minor, &featureFlags, &eventLog, &edi ) == 0) {
			return 0;
		}

		/* edi = 0 means event log is empty */
		if( edi == 0 ) {
			grub_printf( "Event log empty\n" );
			return 0;
		}

		logAddr = eventLog;
		TCG_PCClientPCREvent *event;
		/* index = 0: print all entries */
		if ( index == 0 ) {

			/* eventLog = absolute pointer to the beginning of the event log. */
			event = (TCG_PCClientPCREvent *)logAddr;

			/* If there is exactly one entry */
			if( edi == eventLog ) {
				grub_printf( "pcrIndex: %x \n", event->pcrIndex );
				grub_printf( "eventType: %x \n", event->eventType );
				grub_printf( "digest: " );
				print_sha1( event->digest );
				grub_printf( "\n\n" );
			} else {	/* If there is more than one entry */
				do {
					grub_printf( "pcrIndex: %x \n", event->pcrIndex );
					grub_printf( "eventType: %x \n", event->eventType );
					grub_printf( "digest: " );
					print_sha1( event->digest );
					grub_printf( "\n\n" );

					logAddr += TCG_PCR_EVENT_SIZE + event->eventDataSize;
					event = (TCG_PCClientPCREvent *)logAddr;
				} while( logAddr != edi );

				/* print the last one */
				grub_printf( "pcrIndex: %x \n", event->pcrIndex );
				grub_printf( "eventType: %x \n", event->eventType );
				grub_printf( "digest: " );
				print_sha1( event->digest );
				grub_printf( "\n\n" );
			}
		} else { /* print specific entry */
			if( index < 0 ) {
				grub_printf( "Index must be greater or equal 0\n" );
				return 0;
			}

			logAddr = eventLog;

			int i;
			for( i = 1; i < index; i++ ) {
				event = (TCG_PCClientPCREvent *)logAddr;
				logAddr += TCG_PCR_EVENT_SIZE + event->eventDataSize;

				if( logAddr > edi ) { /* index not valid.  */
					grub_printf( "logentry nonexistent\n" );
					return 0;
				}
			}

			event = (TCG_PCClientPCREvent *)logAddr;
			grub_printf( "pcrIndex: %x \n", event->pcrIndex );
			grub_printf( "eventType: %x \n", event->eventType );
			grub_printf( "digest: " );
			print_sha1( event->digest );
			grub_printf( "\n\n" );
		}
	} else {
		return 0;
	}

  return 1;
}


/* Returns 0 on error. */
grub_err_t
grub_TPM_unseal( const char* sealedFileName ) {

	if( ! grub_TPM_isAvailable() ) {
		return 0;
	}

	/* open file */
	grub_file_t file = grub_file_open( sealedFileName );
	if( ! file ) {
		grub_print_error();
		return 0;
	}

	grub_size_t fileSize = grub_file_size (file);
	if ( ! fileSize )
	{
		grub_file_close (file);
		return 0;
	}

	unsigned char* buf = grub_zalloc (fileSize);
	if ( ! buf )
	{
		grub_file_close (file);
		return 0;
	}

	/* read file */

	if ( grub_file_read (file, buf, fileSize) != (grub_ssize_t) fileSize )
	{
		grub_free( buf );
		grub_file_close (file);
		return 0;
	}

	grub_file_close( file );

	/* TODO */

	/* TPM_UNSEAL Incoming Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t ordinal;
		grub_uint32_t parentHandle;
		grub_uint8_t  sealedData[fileSize];
		grub_uint32_t authHandle;
		grub_uint8_t  nonceOdd[20];
		grub_uint8_t  continueAuthSession;
		grub_uint8_t  parentAuth[20];
		grub_uint32_t dataAuthHandle;
		grub_uint8_t  dataNonceOdd[20];
		grub_uint8_t  continueDataSession;
		grub_uint8_t  dataAuth[20];
	} __attribute__ ((packed)) *tpmInput;

	/* TPM_UNSEAL Outgoing Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t returnCode;
		grub_uint32_t secretSize;
		grub_uint8_t  unsealedData[1024];		/* FIXME: what size to use here? */
		grub_uint8_t  nonceEven[20];
		grub_uint8_t  continueAuthSession;
		grub_uint8_t  resAuth[20];
		grub_uint8_t  dataNonceEven[20];
		grub_uint8_t  continueDataSession;
		grub_uint8_t  dataAuth[20];
	} __attribute__ ((packed)) *tpmOutput;

	struct tcg_passThroughToTPM_InputParamBlock *input;
	grub_uint32_t inputlen = sizeof( *input ) - sizeof( input->TPMOperandIn ) + sizeof( *tpmInput );

	/* FIXME: Why is this Offset value (+47) needed? */
	struct tcg_passThroughToTPM_OutputParamBlock *output;
	grub_uint32_t outputlen = sizeof( *output ) - sizeof( output->TPMOperandOut ) + sizeof( *tpmOutput ) + 47 ;

	/* 	grub_printf( "output=%x ", sizeof( *output )  );
		grub_printf( "output->TPMOperandOut=%x ", sizeof( output->TPMOperandOut )  );
		grub_printf( "tpmOutput=%x ", sizeof( *tpmOutput )  );
		grub_printf( "tpmOutput->pcr_value=%x ", sizeof( tpmOutput->pcr_value )  ); */

	input = grub_zalloc( inputlen );
	if( ! input ) {
		return 0;
	}

	output = grub_zalloc( outputlen );
	if( ! output ) {
		return 0;
	}

	input->IPBLength = inputlen;
	input->OPBLength = outputlen;

	tpmInput = (void*) input->TPMOperandIn;
	tpmInput->tag = swap16( TPM_TAG_RQU_AUTH2_COMMAND );
	tpmInput->paramSize = swap32( sizeof( *tpmInput ) );
	tpmInput->ordinal = swap32( TPM_ORD_Unseal );
	tpmInput->parentHandle = swap32( TPM_KH_SRK );

	grub_memcmp ( tpmInput->sealedData, buf, fileSize );
	grub_free( buf );

	// TODO: tpmInput->authHandle =
	// TODO: tpmInput->nonceOdd
	// TODO: tpmInput->continueAuthSession = 0;
	// TODO: tpmInput->parentAuth
	// TODO: tpmInput->dataAuthHandle
	// TODO: tpmInput->dataNonceOdd
	// TODO: tpmInput->continueDataSession
	// TODO: tpmInput->dataAuth

	grub_uint32_t passThroughTo_TPM_ReturnCode;
	if( ! tcg_passThroughToTPM( input, output, &passThroughTo_TPM_ReturnCode ) ) {
		grub_free( input );
		grub_free( output );
		return 0;
	}

	tpmOutput = (void *)output->TPMOperandOut;
	grub_uint32_t tpm_UnsealReturnCode = swap32( tpmOutput->returnCode );

	if( tpm_UnsealReturnCode != TPM_SUCCESS ) {
		grub_free( input );
		grub_free( output );

		if( tpm_UnsealReturnCode == TPM_AUTHFAIL ) {
			grub_printf( "Authentication failed\n" );
		} else {
			grub_printf( "Unseal failed: %x \n", tpm_UnsealReturnCode );
		}

		return 0;
	}

	grub_free( input );
	grub_free( output );

	grub_printf("OK\n");

	return 1;
}


/* End TCG Extension */
