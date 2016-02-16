/* Begin TCG Extension */

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

#include <grub/types.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/sha1.h>
#include <grub/misc.h>

#include <grub/tpm.h>
#include <grub/i386/pc/tpm.h>
#include <grub/i386/pc/memory.h>
#include <grub/i386/pc/int.h>

#ifdef TGRUB_DEBUG
	#include <grub/time.h>
#endif

/************************* constants *************************/

/* Ordinals */
static const grub_uint32_t TPM_ORD_PcrRead = 0x00000015;

/************************* struct typedefs *************************/

/* TCG_HashLogExtendEvent Input Parameter Block (Format 2) */
typedef struct {
 	grub_uint16_t ipbLength;
 	grub_uint16_t reserved;
 	grub_uint32_t hashDataPtr;
 	grub_uint32_t hashDataLen;
 	grub_uint32_t pcrIndex;
 	grub_uint32_t reserved2;
 	grub_uint32_t logDataPtr;
 	grub_uint32_t logDataLen;
 } GRUB_PACKED EventIncoming;

/* TCG_HashLogExtendEvent Output Parameter Block */
typedef struct {
 	grub_uint16_t opbLength;
 	grub_uint16_t reserved;
 	grub_uint32_t eventNum;
 	grub_uint8_t  hashValue[SHA1_DIGEST_SIZE];
} GRUB_PACKED EventOutgoing;

typedef struct {
	grub_uint32_t pcrIndex;
	grub_uint32_t eventType;
	grub_uint8_t digest[SHA1_DIGEST_SIZE];
	grub_uint32_t eventDataSize;
	grub_uint8_t event[0];
} GRUB_PACKED Event;

/* TPM_PCRRead Incoming Operand */
typedef struct {
	grub_uint16_t tag;
	grub_uint32_t paramSize;
	grub_uint32_t ordinal;
	grub_uint32_t pcrIndex;
} GRUB_PACKED PCRReadIncoming;

/* TPM_PCRRead Outgoing Operand */
typedef struct {
	grub_uint16_t tag;
	grub_uint32_t paramSize;
	grub_uint32_t returnCode;
	grub_uint8_t pcr_value[SHA1_DIGEST_SIZE];
} GRUB_PACKED PCRReadOutgoing;

/************************* static functions *************************/

/* Invokes TCG_HashLogExtendEvent
 *
 * we hash ourself
 *
 *  grub_fatal() on error
 *  Page 116 TCG_PCClientImplementation_1-21_1_00
 */
static void
grub_TPM_int1A_hashLogExtendEvent( const grub_uint8_t* inDigest, grub_uint8_t pcrIndex, const char* description ) {

	CHECK_FOR_NULL_ARGUMENT( inDigest );
	CHECK_FOR_NULL_ARGUMENT( description );

	if( pcrIndex > 23 )
	{
		grub_fatal( "grub_TPM_int1A_hashLogExtendEvent: pcr > 23 is invalid" );
	}

	/* Prepare Event struct */
	grub_uint32_t strSize = grub_strlen(description);
	grub_uint32_t eventStructSize = strSize + sizeof(Event);
	Event* event = grub_zalloc(eventStructSize);

	if (!event)
	{
		grub_fatal( "grub_TPM_int1A_hashLogExtendEvent: memory allocation failed" );
	}

	event->pcrIndex = pcrIndex;
	event->eventType = 0x0d; /* EV_IPL */
	event->eventDataSize = strSize;
	grub_memcpy(event->digest, inDigest, SHA1_DIGEST_SIZE );
	grub_memcpy(event->event, description, strSize);

	/* Prepare EventIncoming struct */
	EventIncoming incoming;
	incoming.ipbLength = sizeof(incoming);
	incoming.hashDataPtr = 0;
	incoming.hashDataLen = 0;
	incoming.pcrIndex = pcrIndex;
	incoming.logDataPtr = (grub_addr_t) event;
	incoming.logDataLen = eventStructSize;

	EventOutgoing outgoing;
	struct grub_bios_int_registers regs;
	regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;
	regs.eax = 0xBB01;
	regs.ebx = TCPA;
	regs.ecx = 0;
	regs.edx = 0;
	regs.es = (((grub_addr_t) &incoming) & 0xffff0000) >> 4;
	regs.edi = ((grub_addr_t) &incoming) & 0xffff;
	regs.ds = (((grub_addr_t) &outgoing) & 0xffff0000) >> 4;
	regs.esi = ((grub_addr_t) &outgoing) & 0xffff;

	grub_bios_interrupt (0x1A, &regs);

	if ( regs.eax != TCG_PC_OK ) {
        grub_fatal( "TCG_HashLogExtendEvent failed: 0x%x", regs.eax );
	}

#ifdef TGRUB_DEBUG
    DEBUG_PRINT( ( "event number: %u \n", outgoing.eventNum ) );
	DEBUG_PRINT( ( "New PCR[%u]=", pcrIndex ) );
	grub_uint8_t result[SHA1_DIGEST_SIZE] = { 0 };
	grub_TPM_readpcr( pcrIndex, &result[0] );
	print_sha1( result );
	DEBUG_PRINT( ( "\n\n" ) );
	grub_sleep( 4 );
#endif

	grub_free(event);
}

/************************* non-static functions *************************/

/* grub_fatal() on error */
void
grub_TPM_readpcr( const grub_uint8_t index, grub_uint8_t* result ) {

    CHECK_FOR_NULL_ARGUMENT( result )

	PassThroughToTPM_InputParamBlock *passThroughInput = NULL;
	PCRReadIncoming* pcrReadIncoming = NULL;
    grub_uint16_t inputlen = sizeof( *passThroughInput ) - sizeof( passThroughInput->TPMOperandIn ) + sizeof( *pcrReadIncoming );

	PassThroughToTPM_OutputParamBlock *passThroughOutput = NULL;
	PCRReadOutgoing* pcrReadOutgoing = NULL;
    grub_uint16_t outputlen = sizeof( *passThroughOutput ) - sizeof( passThroughOutput->TPMOperandOut ) + sizeof( *pcrReadOutgoing );

	passThroughInput = grub_zalloc( inputlen );
	if( ! passThroughInput ) {
        grub_fatal( "readpcr: memory allocation failed" );
	}

	passThroughInput->IPBLength = inputlen;
	passThroughInput->OPBLength = outputlen;

	pcrReadIncoming = (void *)passThroughInput->TPMOperandIn;
	pcrReadIncoming->tag = grub_swap_bytes16_compile_time( TPM_TAG_RQU_COMMAND );
	pcrReadIncoming->paramSize = grub_swap_bytes32( sizeof( *pcrReadIncoming ) );
	pcrReadIncoming->ordinal = grub_swap_bytes32_compile_time( TPM_ORD_PcrRead );
	pcrReadIncoming->pcrIndex = grub_swap_bytes32( (grub_uint32_t) index);

	passThroughOutput = grub_zalloc( outputlen );
	if( ! passThroughOutput ) {
		grub_free( passThroughInput );
        grub_fatal( "readpcr: memory allocation failed" );
	}

	grub_TPM_int1A_passThroughToTPM( passThroughInput, passThroughOutput );
	grub_free( passThroughInput );

	pcrReadOutgoing = (void *)passThroughOutput->TPMOperandOut;
	grub_uint32_t tpm_PCRreadReturnCode = grub_swap_bytes32( pcrReadOutgoing->returnCode );

	if( tpm_PCRreadReturnCode != TPM_SUCCESS ) {
		grub_free( passThroughOutput );

		if( tpm_PCRreadReturnCode == TPM_BADINDEX ) {
            grub_fatal( "readpcr: bad pcr index" );
		}

        grub_fatal( "readpcr: tpm_PCRreadReturnCode: %u", tpm_PCRreadReturnCode );
	}

	grub_memcpy( result, pcrReadOutgoing->pcr_value, SHA1_DIGEST_SIZE );
	grub_free( passThroughOutput );
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
grub_TPM_int1A_statusCheck( grub_uint32_t* returnCode, grub_uint8_t* major, grub_uint8_t* minor, grub_uint32_t* featureFlags, grub_uint32_t* eventLog, grub_uint32_t* edi ) {

	CHECK_FOR_NULL_ARGUMENT( returnCode )
	CHECK_FOR_NULL_ARGUMENT( major )
	CHECK_FOR_NULL_ARGUMENT( minor )
	CHECK_FOR_NULL_ARGUMENT( featureFlags )
	CHECK_FOR_NULL_ARGUMENT( eventLog )
	CHECK_FOR_NULL_ARGUMENT( edi )

	struct grub_bios_int_registers regs;
	regs.eax = 0xBB00;
	regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;

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

/* Invokes TCG_PassThroughToTPM

   grub_fatal() on error
   Page 112 TCG_PCClientImplementation_1-21_1_00
 */
void
grub_TPM_int1A_passThroughToTPM( const PassThroughToTPM_InputParamBlock* input, PassThroughToTPM_OutputParamBlock* output ) {

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

	/*regs.es = (((grub_addr_t) input) & 0xffff0000) >> 4;
	regs.edi = ((grub_addr_t) input) & 0xffff;
	regs.ds = (((grub_addr_t) output) & 0xffff0000) >> 4;
	regs.esi = ((grub_addr_t) output) & 0xffff;*/

	grub_bios_interrupt (0x1A, &regs);

	if ( regs.eax != TCG_PC_OK ) {
        grub_fatal( "TCG_PassThroughToTPM failed: 0x%x", regs.eax );
	}

	/* copy output_buffer */
	p = grub_map_memory( OUTPUT_PARAM_BLK_ADDR, input->OPBLength );
	grub_memcpy( output, p, input->OPBLength );
	grub_unmap_memory( p, input->OPBLength );
}

/* grub_fatal() on error */
void
grub_TPM_measure_string( const char* string ) {

	CHECK_FOR_NULL_ARGUMENT( string )

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
	DEBUG_PRINT( ( "string to measure: '%s'\n", string ) );
	DEBUG_PRINT( ( "SHA1 of string: " ) );
    print_sha1( convertedResult );
    DEBUG_PRINT( ( "\n" ) );
#endif

	grub_TPM_int1A_hashLogExtendEvent( convertedResult, TPM_COMMAND_MEASUREMENT_PCR, string );
}

/* grub_fatal() on error */
void
grub_TPM_measure_file( const char* filename, const grub_uint8_t index ) {

	CHECK_FOR_NULL_ARGUMENT( filename )

	/* open file 'raw' (without any pre-processing filters) */
	grub_file_filter_disable_compression ();
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
	DEBUG_PRINT( ( "SHA1 of file: " ) );
    print_sha1( convertedResult );
    DEBUG_PRINT( ( "\n" ) );
#endif

	/* measure */
	grub_TPM_int1A_hashLogExtendEvent( convertedResult, index, filename );
}

void
grub_TPM_measure_buffer( const void* buffer, const grub_uint32_t bufferLen, const grub_uint8_t index ) {

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
	DEBUG_PRINT( ( "SHA1 of buffer: " ) );
    print_sha1( convertedResult );
    DEBUG_PRINT( ( "\n" ) );
#endif

	/* measure */
	grub_TPM_int1A_hashLogExtendEvent( convertedResult, index, "measured buffer" );
}
/* End TCG Extension */
