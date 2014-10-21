/* Begin TCG extension */

/* tpm.c -- tpm module.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2005,2007,2008,2009,2010  Free Software Foundation, Inc.
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
#include <grub/extcmd.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/crypto.h>
#include <grub/file.h>

#include <grub/machine/tpm.h>
#include <grub/machine/boot.h>
#include <grub/machine/memory.h>

GRUB_MOD_LICENSE ("GPLv3+");



/* TPM_ENTITY_TYPE values */
static const grub_uint16_t TPM_ET_SRK =  0x0004;

/* Reserved Key Handles */
static const grub_uint32_t TPM_KH_SRK = 0x40000000;

/* Ordinals */
static const grub_uint32_t TPM_ORD_OSAP = 0x0000000B;


/* Returns 0 on error. */
static grub_err_t
grub_TPM_readpcr( unsigned long index ) {		/*TODO: print in cmd function. return result in second parameter  */

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

static grub_err_t
grub_cmd_readpcr( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

	if( !grub_TPM_isAvailable() ) {
		grub_printf( "TPM not available\n" );
		return GRUB_ERR_NONE;
	}

	if ( argc == 0 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "index expected" ) );
	}

	if ( argc > 1 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Too many arguments" ) );
	}

	unsigned long index = grub_strtoul( args[0], NULL, 10 );
	/* if index is invalid */
	if( grub_errno != GRUB_ERR_NONE ) {
		grub_print_error();
		grub_errno = GRUB_ERR_NONE;
		return grub_errno;
	}

	if( grub_TPM_readpcr( index ) == 0 ) {
		grub_printf( "PCR read failed\n" );
	}

	return GRUB_ERR_NONE;
}

/* Returns 0 on error. */
/* index = 0 for all entries */
static grub_err_t
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

static grub_err_t
grub_cmd_tcglog( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

	if( !grub_TPM_isAvailable() ) {
		grub_printf( "TPM not available\n" );
		return GRUB_ERR_NONE;
	}

	if ( argc == 0 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "index expected" ) );
	}

	if ( argc > 1 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Too many arguments" ) );
	}

	unsigned long index = grub_strtoul( args[0], NULL, 10 );
	/* if index is invalid */
	if( grub_errno != GRUB_ERR_NONE ) {
		grub_print_error();
		grub_errno = GRUB_ERR_NONE;
		return grub_errno;
	}

	if( grub_TPM_read_tcglog( index ) == 0 ) {
		grub_printf( "Read tcglog failed\n" );
	}

	return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_measure( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

	if( !grub_TPM_isAvailable() ) {
		grub_printf( "TPM not available\n" );
		return GRUB_ERR_NONE;
	}

	if ( argc != 2 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Wrong number of arguments" ) );
	}

	unsigned long index = grub_strtoul( args[1], NULL, 10 );

	/* if index is invalid */
	if( grub_errno != GRUB_ERR_NONE ) {
		grub_print_error();
		grub_errno = GRUB_ERR_NONE;
		return grub_errno;
	}

	grub_TPM_measureFile( args[0], index );

  return GRUB_ERR_NONE;
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

/* Sets Memory Overwrite Request bit */
/* Returns 0 on error */
static grub_uint32_t
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

static grub_err_t
grub_cmd_setMOR( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

	if( !grub_TPM_isAvailable() ) {
		grub_printf( "TPM not available\n" );
		return GRUB_ERR_NONE;
	}

	if ( argc == 0 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "value expected" ) );
	}

	if ( argc > 1 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Too many arguments" ) );
	}

	unsigned int disableAutoDetect = grub_strtoul( args[0], NULL, 10 );
	/* if disableAutoDetect is invalid */
	if( grub_errno != GRUB_ERR_NONE ) {
		grub_print_error();
		grub_errno = GRUB_ERR_NONE;
		return grub_errno;
	}

	if( disableAutoDetect > 1 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Value must be 0 or 1" ) );
	}

	if( grub_TPM_SetMOR_Bit( disableAutoDetect ) == 0 ) {
		grub_printf( "Setting MOR bit failed\n" );
	}

	return GRUB_ERR_NONE;
}

/* Returns 0 on error. */
static grub_err_t
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

	grub_free( input );

	tpmOutput = (void *)output->TPMOperandOut;
	grub_uint32_t tpm_getRandomReturnCode = swap32( tpmOutput->returnCode );

	if( tpm_getRandomReturnCode != TPM_SUCCESS ) {
		grub_free( output );

		DEBUG_PRINT( ( "tpm_getRandomReturnCode: %x \n", tpm_getRandomReturnCode ) );
		return 0;
	}

	if( swap32( tpmOutput->randomBytesSize ) != randomBytesRequested ) {
		grub_free( output );
		DEBUG_PRINT( ( "tpmOutput->randomBytesSize != randomBytesRequested\n" ) );
		DEBUG_PRINT( ( "tpmOutput->randomBytesSize = %x \n", swap32( tpmOutput->randomBytesSize ) ) );
		DEBUG_PRINT( ( "randomBytesRequested = %x \n", randomBytesRequested ) );
		return 0;
	}

	if( grub_memcpy( random, tpmOutput->randomBytes, randomBytesRequested ) != random ) {
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	grub_free( output );

	return 1;
}


/* Returns 0 on error. */
static grub_err_t
grub_TPM_openOIAP_Session( grub_uint32_t* authHandle, unsigned char* nonceEven ) {

	if( ! grub_TPM_isAvailable() ) {
		return 0;
	}

	if( ! authHandle )
	{
		DEBUG_PRINT( ( "authHandle argument is NULL.\n" ) );
		return 0;
	}

	if( ! nonceEven )
	{
		DEBUG_PRINT( ( "nonceEven argument is NULL.\n" ) );
		return 0;
	}

	/* TPM_OIAP Incoming Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t ordinal;
	} __attribute__ ((packed)) *tpmInput;

	/* TPM_OIAP Outgoing Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t returnCode;
		grub_uint32_t authHandle;
		grub_uint8_t  nonceEven[TPM_NONCE_SIZE];
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
	tpmInput->ordinal = swap32( TPM_ORD_OIAP );

	grub_uint32_t passThroughTo_TPM_ReturnCode;
	if( tcg_passThroughToTPM( input, output, &passThroughTo_TPM_ReturnCode ) == 0 ) {
		grub_free( input );
		grub_free( output );

		DEBUG_PRINT( ( "tcg_passThroughToTPM failed\n" ) );
		return 0;
	}

	grub_free( input );

	tpmOutput = (void *)output->TPMOperandOut;
	grub_uint32_t tpm_OIAP_ReturnCode = swap32( tpmOutput->returnCode );

	if( tpm_OIAP_ReturnCode != TPM_SUCCESS ) {
		grub_free( output );

		DEBUG_PRINT( ( "tpm_OIAP_ReturnCode: %x \n", tpm_OIAP_ReturnCode ) );
		return 0;
	}

	*authHandle = swap32( tpmOutput->authHandle );
	if( grub_memcpy( nonceEven, tpmOutput->nonceEven, TPM_NONCE_SIZE ) != nonceEven ) {
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	grub_free( output );

	return 1;
}

/* Returns 0 on error. */
static grub_err_t
grub_TPM_openOSAP_Session( const grub_uint32_t entityType, const grub_uint16_t entityValue, grub_uint32_t* authHandle, grub_uint8_t* nonceEven, grub_uint8_t* nonceEvenOSAP ) {

	if( ! grub_TPM_isAvailable() ) {
		return 0;
	}

	if( ! authHandle )	{
		DEBUG_PRINT( ( "authHandle argument is NULL.\n" ) );
		return 0;
	}

	if( ! nonceEven ) {
		DEBUG_PRINT( ( "nonceEven argument is NULL.\n" ) );
		return 0;
	}

	if( ! nonceEvenOSAP ) {
		DEBUG_PRINT( ( "nonceEven argument is NULL.\n" ) );
		return 0;
	}

	/* TPM_OSAP Incoming Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t ordinal;
		grub_uint16_t entityType;
		grub_uint32_t entityValue;
		grub_uint8_t  nonceOddOSAP[TPM_NONCE_SIZE];
	} __attribute__ ((packed)) *tpmInput;

	/* TPM_OSAP Outgoing Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t returnCode;
		grub_uint32_t authHandle;
		grub_uint8_t  nonceEven[TPM_NONCE_SIZE];
		grub_uint8_t  nonceEvenOSAP[TPM_NONCE_SIZE];
	} __attribute__ ((packed)) *tpmOutput;

	struct tcg_passThroughToTPM_InputParamBlock* input;
	grub_uint32_t inputlen = sizeof( *input ) - sizeof( input->TPMOperandIn ) + sizeof( *tpmInput );

	/* FIXME: Why is this Offset value (+47) needed? */
	struct tcg_passThroughToTPM_OutputParamBlock* output;
	grub_uint32_t outputlen = sizeof( *output ) - sizeof( output->TPMOperandOut ) + sizeof( *tpmOutput ) + 47 ;

	input = grub_zalloc( inputlen );
	if( ! input ) {
		DEBUG_PRINT( ( "memory allocation for 'input' failed\n" ) );
		return 0;
	}

	input->IPBLength = inputlen;
	input->OPBLength = outputlen;

	tpmInput = (void *)input->TPMOperandIn;
	tpmInput->tag = swap16( TPM_TAG_RQU_COMMAND );
	tpmInput->paramSize = swap32( sizeof( *tpmInput ) );
	tpmInput->ordinal = swap32( TPM_ORD_OSAP );
	tpmInput->entityType = swap16( entityType );
	tpmInput->entityValue = swap32( entityValue );

	/* get random for nonceOddOSAP */
	if ( ! grub_TPM_getRandom( tpmInput->nonceOddOSAP, TPM_NONCE_SIZE ) ) {
		grub_free( input );
		return 0;
	}

	output = grub_zalloc( outputlen );
	if( ! output ) {
		DEBUG_PRINT( ( "memory allocation for 'output' failed\n" ) );
		return 0;
	}

	grub_uint32_t passThroughTo_TPM_ReturnCode;
	if( tcg_passThroughToTPM( input, output, &passThroughTo_TPM_ReturnCode ) == 0 ) {
		grub_free( input );
		grub_free( output );

		DEBUG_PRINT( ( "tcg_passThroughToTPM failed\n" ) );
		return 0;
	}

	grub_free( input );

	tpmOutput = (void *)output->TPMOperandOut;
	grub_uint32_t tpm_OSAP_ReturnCode = swap32( tpmOutput->returnCode );

	if( tpm_OSAP_ReturnCode != TPM_SUCCESS ) {
		grub_free( output );

		DEBUG_PRINT( ( "tpm_OSAP_ReturnCode: %d \n", tpm_OSAP_ReturnCode ) );
		return 0;
	}

	*authHandle = swap32( tpmOutput->authHandle );

	if( grub_memcpy( nonceEven, tpmOutput->nonceEven, TPM_NONCE_SIZE ) != nonceEven ) {
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	if( grub_memcpy( nonceEvenOSAP, tpmOutput->nonceEvenOSAP, TPM_NONCE_SIZE ) != nonceEvenOSAP ) {
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	grub_free( output );

	return 1;
}

/* Returns 0 on error. */
static grub_err_t
grub_TPM_unseal( const char* sealedFileName, grub_uint8_t* result, grub_size_t* resultSize ) {

	if( ! sealedFileName ) {
		return 0;
	}

	if( result ) {
		return 0;
	}

	if( ! resultSize ) {
		return 0;
	}

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
		DEBUG_PRINT( ( "Retrieving file size failed\n" ) );
		grub_file_close (file);
		return 0;
	}
	DEBUG_PRINT( ( "sealed file size = %d\n", fileSize ) );

	unsigned char* buf = grub_zalloc (fileSize);
	if ( ! buf )
	{
		DEBUG_PRINT( ( "Memory allocation failed\n" ) );
		grub_file_close (file);
		return 0;
	}

	/* read file */
	if ( grub_file_read (file, buf, fileSize) != (grub_ssize_t) fileSize )
	{
		DEBUG_PRINT( ( "Read file failed\n" ) );
		grub_free( buf );
		grub_file_close (file);
		return 0;
	}

	grub_file_close( file );

	/* TPM_UNSEAL Incoming Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t ordinal;
		grub_uint32_t parentHandle;
		grub_uint8_t  sealedData[fileSize];
		grub_uint32_t authHandle;
		grub_uint8_t  nonceOdd[TPM_NONCE_SIZE];
		grub_uint8_t  continueAuthSession;
		grub_uint8_t  parentAuth[TPM_AUTHDATA_SIZE];
		grub_uint32_t dataAuthHandle;
		grub_uint8_t  dataNonceOdd[TPM_NONCE_SIZE];
		grub_uint8_t  continueDataSession;
		grub_uint8_t  dataAuth[TPM_AUTHDATA_SIZE];
	} __attribute__ ((packed)) *tpmInput;

	/* TPM_UNSEAL Outgoing Operand */
	struct {
		grub_uint16_t tag;
		grub_uint32_t paramSize;
		grub_uint32_t returnCode;
		grub_uint32_t secretSize;
		grub_uint8_t  unsealedData[fileSize + 512];		/* FIXME: what size to use here? */
		grub_uint8_t  nonceEven[TPM_NONCE_SIZE];
		grub_uint8_t  continueAuthSession;
		grub_uint8_t  resAuth[TPM_AUTHDATA_SIZE];
		grub_uint8_t  dataNonceEven[TPM_NONCE_SIZE];
		grub_uint8_t  continueDataSession;
		grub_uint8_t  dataAuth[TPM_AUTHDATA_SIZE];
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
		DEBUG_PRINT( ( "Memory allocation failed\n" ) );
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

	/* get first authHandle and authLastNonceEven */
	unsigned char authLastNonceEven[TPM_NONCE_SIZE];
	grub_uint32_t authHandle = 0;
	if( ! grub_TPM_openOIAP_Session( &authHandle, &authLastNonceEven[0] ) ) {
		grub_free( input );
		return 0;
	}

	tpmInput->authHandle = swap32( authHandle );

	/* get random for nonceOdd */
	unsigned char nonceOdd[TPM_NONCE_SIZE];
	if ( ! grub_TPM_getRandom( &nonceOdd[0], TPM_NONCE_SIZE ) ) {
		grub_free( input );
		return 0;
	}

	if( grub_memcpy( tpmInput->nonceOdd, nonceOdd, TPM_NONCE_SIZE ) != tpmInput->nonceOdd ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	tpmInput->continueAuthSession = 0;		// swap32 if 1

	/* Generate HMAC */
	/* HMAC( key.usageAuth, SHA1( ordinal, inData ), authLastNonceEven, nonceOdd, continueAuthSession ) */

	/* data to hmac */
	grub_size_t dataSize = SHA1_DIGEST_SIZE /* keyUsageAuth size */ +
			SHA1_DIGEST_SIZE /* hashed ordinal and inData */+
			TPM_NONCE_SIZE /* authLastNonceEven */ +
			TPM_NONCE_SIZE /* nonceOdd */ +
			sizeof( grub_uint32_t ) /* continueAuthSession */;

	/* key = well known secret = 20 zero bytes */
	grub_uint8_t keyUsageAuth[SHA1_DIGEST_SIZE];
	if( grub_memset( keyUsageAuth, 0, SHA1_DIGEST_SIZE ) != keyUsageAuth ) {
		grub_free( input );
		DEBUG_PRINT( ( "memset failed.\n" ) );
		return 0;
	}

	grub_uint8_t data[dataSize];
	grub_uint8_t* dataPointer = &data[0];

	if( grub_memcpy( dataPointer, &keyUsageAuth[0], SHA1_DIGEST_SIZE ) != dataPointer ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	dataPointer += SHA1_DIGEST_SIZE;

	/* SHA1( ordinal, inData ) */
	grub_uint32_t concatenatedOrdinalAndInDataSize = sizeof( grub_uint32_t ) + fileSize;
	grub_uint8_t* concatenatedOrdinalAndInData = grub_zalloc( concatenatedOrdinalAndInDataSize );
	if( ! concatenatedOrdinalAndInData ) {
		grub_free( input );
		DEBUG_PRINT( ( "Memory allocation failed\n" ) );
		return 0;
	}

	/* copy ordinal */
	if( grub_memcpy( concatenatedOrdinalAndInData, &tpmInput->ordinal, sizeof( grub_uint32_t ) ) != concatenatedOrdinalAndInData ) {
		grub_free( input );
		grub_free( concatenatedOrdinalAndInData );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	/* copy inData */
	if( grub_memcpy( concatenatedOrdinalAndInData + sizeof( grub_uint32_t ) , tpmInput->sealedData, fileSize ) != concatenatedOrdinalAndInData + sizeof( grub_uint32_t ) ) {
		grub_free( input );
		grub_free( concatenatedOrdinalAndInData );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	grub_uint8_t hashResult[SHA1_DIGEST_SIZE];
	grub_crypto_hash( GRUB_MD_SHA1, &hashResult[0], concatenatedOrdinalAndInData, concatenatedOrdinalAndInDataSize );
	grub_free( concatenatedOrdinalAndInData );

	if( grub_memcpy( dataPointer, hashResult, SHA1_DIGEST_SIZE ) != dataPointer ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	dataPointer += SHA1_DIGEST_SIZE;

	if( grub_memcpy( dataPointer, &authLastNonceEven[0], TPM_NONCE_SIZE ) != dataPointer ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	dataPointer += TPM_NONCE_SIZE;

	if( grub_memcpy( dataPointer, tpmInput->nonceOdd, TPM_NONCE_SIZE ) != dataPointer ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	dataPointer += TPM_NONCE_SIZE;

	if( grub_memcpy( dataPointer, &tpmInput->continueAuthSession, sizeof( grub_uint32_t ) ) != dataPointer ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	gcry_err_code_t hmacErrorCode = grub_crypto_hmac_buffer( GRUB_MD_SHA1, &keyUsageAuth[0], SHA1_DIGEST_SIZE, &data[0],
			dataSize, tpmInput->parentAuth );

	if( hmacErrorCode ) {
		grub_free( input );
		DEBUG_PRINT( ( "Calculate hmac failed\n" ) );
		return 0;
	}

	/* get second dataAuthHandle and dataLastNonceEven */
	unsigned char dataLastNonceEven[TPM_NONCE_SIZE];
	grub_uint32_t dataAuthHandle = 0;
	if( ! grub_TPM_openOIAP_Session( &dataAuthHandle, &dataLastNonceEven[0] ) ) {
		grub_free( input );
		return 0;
	}

	tpmInput->dataAuthHandle = swap32( dataAuthHandle );

	/* get random for dataNonceOdd */
	unsigned char dataNonceOdd[TPM_NONCE_SIZE];
	if ( ! grub_TPM_getRandom( &dataNonceOdd[0], TPM_NONCE_SIZE ) ) {
		grub_free( input );
		return 0;
	}

	if( grub_memcpy( tpmInput->dataNonceOdd, dataNonceOdd, TPM_NONCE_SIZE ) != tpmInput->dataNonceOdd ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;;
	}

	tpmInput->continueDataSession = 0;		// swap32 if 1

	/* Generate second HMAC */
	/* HMAC( entity.usageAuth, SHA1( ordinal, inData ), dataLastNonceEven, dataNonceOdd, continueDataSession ) */

	/* clear data array. dataSize is the same */
	if( grub_memset( data, 0, dataSize ) != data ) {
		grub_free( input );
		DEBUG_PRINT( ( "memset failed.\n" ) );
		return 0;
	}

	dataPointer = &data[0];

	/* use keyUsageAuth as entityAuth = well known secret */
	if( grub_memcpy( dataPointer, &keyUsageAuth[0], SHA1_DIGEST_SIZE ) != dataPointer ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	dataPointer += SHA1_DIGEST_SIZE;

	if( grub_memcpy( dataPointer, &hashResult[0], SHA1_DIGEST_SIZE ) != dataPointer ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	dataPointer += SHA1_DIGEST_SIZE;

	if( grub_memcpy( dataPointer, &dataLastNonceEven[0], TPM_NONCE_SIZE ) != dataPointer ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	dataPointer += TPM_NONCE_SIZE;

	if( grub_memcpy( dataPointer, tpmInput->dataNonceOdd, TPM_NONCE_SIZE ) != dataPointer ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	dataPointer += TPM_NONCE_SIZE;

	if( grub_memcpy( dataPointer, &tpmInput->continueDataSession, sizeof( grub_uint32_t ) ) != dataPointer ) {
		grub_free( input );
		DEBUG_PRINT( ( "memcpy failed.\n" ) );
		return 0;
	}

	hmacErrorCode = grub_crypto_hmac_buffer( GRUB_MD_SHA1, &keyUsageAuth[0], SHA1_DIGEST_SIZE, &data[0],
			dataSize, tpmInput->dataAuth );

	if( hmacErrorCode ) {
		grub_free( input );
		DEBUG_PRINT( ( "Calculate hmac failed\n" ) );
		return 0;
	}

	output = grub_zalloc( outputlen );
	if( ! output ) {
		grub_free( input );
		DEBUG_PRINT( ( "Memory allocation failed\n" ) );
		return 0;
	}

	grub_uint32_t passThroughTo_TPM_ReturnCode;
	if( ! tcg_passThroughToTPM( input, output, &passThroughTo_TPM_ReturnCode ) ) {
		DEBUG_PRINT( ( "tcg_passThroughToTPM failed with: %x\n", passThroughTo_TPM_ReturnCode ) );
		grub_free( input );
		grub_free( output );
		return 0;
	}
	grub_free( input );

	tpmOutput = (void *)output->TPMOperandOut;
	grub_uint32_t tpm_UnsealReturnCode = swap32( tpmOutput->returnCode );

	if( tpm_UnsealReturnCode != TPM_SUCCESS ) {
		grub_free( output );

		if( tpm_UnsealReturnCode == TPM_AUTHFAIL ) {
			DEBUG_PRINT( ( "Authentication failed\n" ) );
		} else {
			DEBUG_PRINT( ( "Unseal failed: %x \n", tpm_UnsealReturnCode ) );
		}

		return 0;
	}

	/* TODO: return result */

	grub_free( output );
	grub_printf("OK\n");

	return 1;
}

static grub_err_t
grub_cmd_unseal( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

	if( !grub_TPM_isAvailable() ) {
		grub_printf( "TPM not available\n" );
		return GRUB_ERR_NONE;
	}

	if ( argc != 2 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Wrong number of arguments" ) );
	}

	grub_uint8_t* result = 0;
	grub_size_t resultSize;
	if( grub_TPM_unseal( args[0], result, &resultSize ) == 0 ) {
		grub_printf( "Unsealing failed\n" );
		return GRUB_ERR_NONE;
	}

	/* TODO: write result to file */

  return GRUB_ERR_NONE;
}


#ifdef TGRUB_DEBUG
static grub_err_t
grub_cmd_getRandom( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

	if( ! grub_TPM_isAvailable() ) {
		grub_printf( "TPM not available\n" );
		return GRUB_ERR_NONE;
	}

	if ( argc == 0 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "value expected" ) );
	}

	if ( argc > 1 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Too many arguments" ) );
	}

	grub_uint32_t randomBytesRequested = grub_strtoul( args[0], NULL, 10 );
	/* if randomBytesRequested is invalid */
	if( grub_errno != GRUB_ERR_NONE ) {
		grub_print_error();
		grub_errno = GRUB_ERR_NONE;
		return grub_errno;
	}

	if( randomBytesRequested <= 0 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Value must be greater 0" ) );
	}

	unsigned char random[randomBytesRequested];

	if( grub_TPM_getRandom( &random[0], randomBytesRequested ) == 0 ) {
		grub_printf( "getRandom failed\n" );
		return GRUB_ERR_NONE;
	}

	unsigned int j;
	for( j = 0; j < randomBytesRequested; ++j ) {
		grub_printf( "%02x", random[j] );
	}

	return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_openOIAP(grub_command_t cmd __attribute__ ((unused)), int argc __attribute__ ((unused)), char** args __attribute__ ((unused))) {

	if( ! grub_TPM_isAvailable() ) {
		grub_printf( "TPM not available\n" );
		return GRUB_ERR_NONE;
	}

	grub_uint32_t authHandle = 0;
	grub_uint8_t nonceEven[TPM_NONCE_SIZE];

	if( grub_TPM_openOIAP_Session( &authHandle, &nonceEven[0] ) == 0 ) {
		grub_printf( "open OIAP session failed\n" );
		return GRUB_ERR_NONE;
	}

	grub_printf( "authHandle: %x \n", authHandle );

	grub_printf( "nonceEven: " );
	unsigned int j;
	for( j = 0; j < TPM_NONCE_SIZE; ++j ) {
		grub_printf( "%02x", nonceEven[j] );
	}

	return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_openOSAP(grub_command_t cmd __attribute__ ((unused)), int argc __attribute__ ((unused)), char** args __attribute__ ((unused))) {

	if( ! grub_TPM_isAvailable() ) {
		grub_printf( "TPM not available\n" );
		return GRUB_ERR_NONE;
	}

	grub_uint32_t authHandle = 0;
	grub_uint8_t nonceEven[TPM_NONCE_SIZE];
	grub_uint8_t nonceEvenOSAP[TPM_NONCE_SIZE];

	if( grub_TPM_openOSAP_Session( TPM_ET_SRK, TPM_KH_SRK, &authHandle, &nonceEven[0], &nonceEvenOSAP[0] ) == 0 ) {
		grub_printf( "open OSAP session failed\n" );
		return GRUB_ERR_NONE;
	}

	grub_printf( "authHandle: %x \n", authHandle );

	grub_printf( "nonceEven: " );
	unsigned int j;
	for( j = 0; j < TPM_NONCE_SIZE; ++j ) {
		grub_printf( "%02x", nonceEven[j] );
	}

	grub_printf( "\n nonceEvenOSAP: " );
	for( j = 0; j < TPM_NONCE_SIZE; ++j ) {
		grub_printf( "%02x", nonceEvenOSAP[j] );
	}

	return GRUB_ERR_NONE;
}
#endif

static grub_command_t cmd_readpcr, cmd_tcglog, cmd_measure, cmd_setMOR, cmd_unseal;

#ifdef TGRUB_DEBUG
	static grub_command_t cmd_random, cmd_oiap, cmd_osap;
#endif

GRUB_MOD_INIT(tpm)
{
	cmd_readpcr = grub_register_command( "readpcr", grub_cmd_readpcr, N_( "pcrindex" ),
  		N_( "Display current value of the PCR (Platform Configuration Register) within "
  		    "TPM (Trusted Platform Module) at index, pcrindex." ) );

	cmd_tcglog = grub_register_command( "tcglog", grub_cmd_tcglog, N_( "logindex" ),
		N_( "Displays TCG event log entry at position, logindex. Type in 0 for all entries." ) );

	cmd_measure = grub_register_command( "measure", grub_cmd_measure, N_( "FILE pcrindex" ),
	  	N_( "Perform TCG measurement operation with the file FILE and with PCR( pcrindex )." ) );

	cmd_setMOR = grub_register_command( "setmor", grub_cmd_setMOR, N_( "disableAutoDetect" ),
		  	N_( "Sets Memory Overwrite Request Bit with auto detect enabled (0) or disabled (1)" ) );

	cmd_unseal = grub_register_command( "unseal", grub_cmd_unseal, N_( "sealedFile unsealedFile" ),
			  	N_( "Unseals 'sealedFile' and writes result to 'unsealedFile' " ) );

#ifdef TGRUB_DEBUG
	cmd_random = grub_register_command( "random", grub_cmd_getRandom, N_( "bytesRequested" ),
			  	N_( "Gets random bytes from TPM." ) );
	cmd_oiap = grub_register_command( "oiap", grub_cmd_openOIAP, 0,
				  	N_( "Opens OIAP Session" ) );
	cmd_osap = grub_register_command( "osap", grub_cmd_openOSAP, 0,
					  	N_( "Opens OSAP Session" ) );
#endif

}

GRUB_MOD_FINI(tpm)
{
	grub_unregister_command( cmd_readpcr );
	grub_unregister_command( cmd_tcglog );
	grub_unregister_command( cmd_measure );
	grub_unregister_command( cmd_setMOR );
	grub_unregister_command( cmd_unseal );

#ifdef TGRUB_DEBUG
	grub_unregister_command( cmd_random );
	grub_unregister_command( cmd_oiap );
	grub_unregister_command( cmd_osap );
#endif

}

/* End TCG extension */
