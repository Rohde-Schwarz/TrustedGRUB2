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
static const grub_uint32_t TPM_ORD_Extend = 0x00000014;
/************************* struct typedefs *************************/

typedef struct {
    grub_uint32_t pcrIndex;
    grub_uint32_t eventType;
    grub_uint8_t digest[SHA1_DIGEST_SIZE];
    grub_uint32_t eventDataSize;
    grub_uint8_t event[0];
} GRUB_PACKED Event;

/* TCG_HashLogEvent Input Parameter Block (Format 2) */
typedef struct {
    grub_uint16_t ipbLength;
    grub_uint16_t reserved;
    grub_uint32_t hashDataPtr;
    grub_uint32_t hashDataLen;
    grub_uint32_t pcrIndex;
    grub_uint32_t logEventType;
    grub_uint32_t logDataPtr;
    grub_uint32_t logDataLen;
 } GRUB_PACKED LogEventIncoming;

/* TCG_HashLogEvent Output Parameter Block */
typedef struct {
    grub_uint16_t opbLength;
    grub_uint16_t reserved;
    grub_uint32_t eventNum;
} GRUB_PACKED LogEventOutgoing;

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

/* TPM_Extend Incoming Operand */
typedef struct {
    grub_uint16_t tag;
    grub_uint32_t paramSize;
    grub_uint32_t ordinal;
    grub_uint32_t pcrIndex;
    grub_uint8_t inDigest[SHA1_DIGEST_SIZE];
} GRUB_PACKED PCRExtendIncoming;

/* TPM_Extend Outgoing Operand */
typedef struct {
    grub_uint16_t tag;
    grub_uint32_t paramSize;
    grub_uint32_t returnCode;
    grub_uint32_t ordinal;
    grub_uint8_t pcr_value[SHA1_DIGEST_SIZE];
} GRUB_PACKED PCRExtendOutgoing;

/************************* static functions *************************/

static void
grub_TPM_int1A_compactHashLogExtendEvent( const grub_uint8_t* buffer, const grub_uint32_t bufferLen, const grub_uint8_t pcrIndex ) {

    CHECK_FOR_NULL_ARGUMENT( buffer );
    
    if( pcrIndex > 23 )
    {
        grub_fatal( "grub_TPM_int1A_compactHashLogExtendEvent: pcr > 23 is invalid" );
    }
    
    /* Allocate the buffer on the stack 
     * NOTE: If we're here, then TCG_hashLogEvent failed and event logging
     * is mandatory.  We should only be using this in the case of very
     * small buffers (like strings)
     */

    grub_uint8_t stackBuffer[4096];
    if ( bufferLen > 4096 ){
        grub_fatal("Maximum buffer size in compactLogHashEvent is 4096 bytes");
    }
    grub_memcpy(stackBuffer, buffer, bufferLen );

    struct grub_bios_int_registers regs;
    regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;
    regs.eax = 0xBB07;
    regs.es = (((grub_addr_t) &stackBuffer) & 0xffff0000) >> 4;
    regs.edi = ((grub_addr_t) &stackBuffer) & 0xffff;

    regs.ebx = TCPA;
    regs.ecx = bufferLen;
    regs.edx = pcrIndex;

    /* informative value - currently 0 */
    regs.esi = 0;

    grub_bios_interrupt (0x1A, &regs);

    if ( regs.eax != TCG_PC_OK ) {
        grub_fatal( "TCG_CompactHashLogExtendEvent failed: 0x%x", regs.eax );
    }

#ifdef TGRUB_DEBUG
    DEBUG_PRINT( ( "event number: %u \n", regs.edx ) );
    DEBUG_PRINT( ( "New PCR[%u]=", pcrIndex ) );
    grub_uint8_t result[SHA1_DIGEST_SIZE] = { 0 };
    grub_TPM_readpcr( pcrIndex, &result[0] );
    print_sha1( result );
    DEBUG_PRINT( ( "\n\n" ) );
    grub_sleep( 4 );
#endif
}

/* Invokes TCG_HashLogEvent and TPM_Extend.
 * If logging fails and is mandatory, call TCG_compactLogHashEvent instead
 *
 * we hash ourself
 *
 *  grub_fatal() on error of the TPM_Extend
 *  print warning on error of TCG_HashLogEvent
 *  Page 122 TCG_PCClientImplementation_1-21_1_00
 */
static void
grub_TPM_hashExtendAndLogPCR( const void* buffer, const grub_uint32_t bufferLen, const grub_uint8_t pcrIndex, const char* description, const int mandatoryLog ) {

    CHECK_FOR_NULL_ARGUMENT( buffer );
    CHECK_FOR_NULL_ARGUMENT( description );

    if( pcrIndex > 23 )
    {
        grub_fatal( "grub_TPM_hashExtendAndLogPCR: pcr > 23 is invalid" );
    }
   
    /* hash buffer */
    grub_uint32_t result[5] = { 0 };
    grub_err_t err = sha1_hash_buffer( buffer, bufferLen, result );

    if( err != GRUB_ERR_NONE ) {
        grub_fatal( "grub_TPM_hashExtendAndLogPCR: sha1_hash_buffer failed." );
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
    DEBUG_PRINT( ( "SHA1 of buffer/string: " ) );
    print_sha1( convertedResult );
    DEBUG_PRINT( ( "\n" ) );
#endif

    /* First, attempt to log the event we're getting ready to extend */
    
    /* Prepare Event struct */
    grub_uint32_t strSize = grub_strlen(description);
    grub_uint32_t eventStructSize = strSize + sizeof(Event);
    Event* event = grub_zalloc(eventStructSize);

    if (!event)
    {
        grub_fatal( "grub_TPM_extendAndLogPCR: memory allocation failed" );
    }

    event->pcrIndex = pcrIndex;
    event->eventType = 0x0d; /* EV_IPL */
    event->eventDataSize = strSize;
    grub_memcpy(event->digest, convertedResult, SHA1_DIGEST_SIZE );
    grub_memcpy(event->event, description, strSize);

    /* Prepare EventIncoming struct */
    LogEventIncoming incoming;
    incoming.ipbLength = sizeof(incoming);
    incoming.hashDataPtr = 0;
    incoming.hashDataLen = 0;
    incoming.pcrIndex = pcrIndex;
    incoming.logEventType = 0x0d; /* EV_IPL */
    incoming.logDataPtr = (grub_addr_t) event;
    incoming.logDataLen = eventStructSize;

    LogEventOutgoing outgoing;
    struct grub_bios_int_registers regs;
    regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;
    regs.eax = 0xBB04;
    regs.ebx = TCPA;
    regs.ecx = 0;
    regs.edx = 0;
    regs.es = (((grub_addr_t) &incoming) & 0xffff0000) >> 4;
    regs.edi = ((grub_addr_t) &incoming) & 0xffff;
    regs.ds = (((grub_addr_t) &outgoing) & 0xffff0000) >> 4;
    regs.esi = ((grub_addr_t) &outgoing) & 0xffff;

/* BIOS bug workaround - do not attempt TCG_hashLogEvent if it would hang */
#ifndef TGRUB_NOEVENTLOG
    grub_bios_interrupt (0x1A, &regs);
#endif

    if ( regs.eax != TCG_PC_OK && mandatoryLog) {
#ifndef TGRUB_NOEVENTLOG
        grub_printf( "WARNING: TCG_HashLogEvent failed: 0x%x\n", regs.eax );
#endif
        grub_printf( "Event Logging is mandatory, falling back to TCG_compactLogHashEvent\n" );
        
        grub_TPM_int1A_compactHashLogExtendEvent( buffer, bufferLen, pcrIndex );
                
    } else {

        if ( regs.eax != TCG_PC_OK) {
#ifndef TGRUB_NOEVENTLOG
            grub_printf( "WARNING: TCG_HashLogEvent failed: 0x%x\n", regs.eax );
            grub_printf( "Event Logging not mandatory, using TPM_Extend\n" );
#endif
        } else {
#ifdef TGRUB_DEBUG
            grub_uint8_t pcrResult[SHA1_DIGEST_SIZE] = {0};
            DEBUG_PRINT( ( "event number: %u \n", outgoing.eventNum ) );
            DEBUG_PRINT( ( "Old PCR[%u]=", pcrIndex ) );
            grub_TPM_readpcr( pcrIndex, &pcrResult[0] );
            print_sha1( pcrResult );
            DEBUG_PRINT( ( "\n\n" ) );
            grub_sleep( 4 );
#endif
        }

        /* TPM_Extend the log that we just did */
        
        grub_uint8_t hashResult[SHA1_DIGEST_SIZE] = { 0 };
        /* Do the TPM_Extend via a pass-through */
        grub_TPM_extendpcr(pcrIndex, convertedResult, hashResult);
    
#ifdef TGRUB_DEBUG
        DEBUG_PRINT( ( "TPM_Extend on PCR %u \n", pcrIndex ) );
        DEBUG_PRINT( ( "New PCR[%u]=", pcrIndex ) );
        print_sha1(hashResult);
        DEBUG_PRINT( ( "\n\n" ) );
#endif    

    }

    grub_free(event);
}

/* Invokes TCG_hashLogEvent and TPM_Extend.
 *
 * we hash ourself
 *
 *  grub_fatal() on error of the TPM_Extend
 *  print warning on error of TCG_HashLogEvent
 *  Page 122 TCG_PCClientImplementation_1-21_1_00
 */
static void
grub_TPM_extendAndLogPCR( const grub_uint8_t* inDigest, const grub_uint8_t pcrIndex, const char* description ) {

    CHECK_FOR_NULL_ARGUMENT( inDigest );
    CHECK_FOR_NULL_ARGUMENT( description );

    if( pcrIndex > 23 )
    {
        grub_fatal( "grub_TPM_extendAndLogPCR: pcr > 23 is invalid" );
    }
   
     /* First, attempt to log the event we're getting ready to extend */
    
    /* Prepare Event struct */
    grub_uint32_t strSize = grub_strlen(description);
    grub_uint32_t eventStructSize = strSize + sizeof(Event);
    Event* event = grub_zalloc(eventStructSize);

    if (!event)
    {
        grub_fatal( "grub_TPM_extendAndLogPCR: memory allocation failed" );
    }

    event->pcrIndex = pcrIndex;
    event->eventType = 0x0d; /* EV_IPL */
    event->eventDataSize = strSize;
    grub_memcpy(event->digest, inDigest, SHA1_DIGEST_SIZE );
    grub_memcpy(event->event, description, strSize);

    /* Prepare EventIncoming struct */
    LogEventIncoming incoming;
    incoming.ipbLength = sizeof(incoming);
    incoming.hashDataPtr = 0;
    incoming.hashDataLen = 0;
    incoming.pcrIndex = pcrIndex;
    incoming.logEventType = 0x0d; /* EV_IPL */
    incoming.logDataPtr = (grub_addr_t) event;
    incoming.logDataLen = eventStructSize;

    LogEventOutgoing outgoing;
    struct grub_bios_int_registers regs;
    regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;
    regs.eax = 0xBB04;
    regs.ebx = TCPA;
    regs.ecx = 0;
    regs.edx = 0;
    regs.es = (((grub_addr_t) &incoming) & 0xffff0000) >> 4;
    regs.edi = ((grub_addr_t) &incoming) & 0xffff;
    regs.ds = (((grub_addr_t) &outgoing) & 0xffff0000) >> 4;
    regs.esi = ((grub_addr_t) &outgoing) & 0xffff;

/* BIOS bug workaround - do not attempt TCG_hashLogEvent if it would hang */
#ifndef TGRUB_NOEVENTLOG
    grub_bios_interrupt (0x1A, &regs);
#endif

    if ( regs.eax != TCG_PC_OK ) {
#ifndef TGRUB_NOEVENTLOG
        grub_printf( "WARNING: TCG_HashLogEvent failed: 0x%x\n", regs.eax );
#endif              
    } else {
#ifdef TGRUB_DEBUG
        grub_uint8_t pcrResult[SHA1_DIGEST_SIZE] = {0};
        DEBUG_PRINT( ( "event number: %u \n", outgoing.eventNum ) );
        DEBUG_PRINT( ( "Old PCR[%u]=", pcrIndex ) );
        grub_TPM_readpcr( pcrIndex, &pcrResult[0] );
        print_sha1( pcrResult );
        DEBUG_PRINT( ( "\n\n" ) );
        grub_sleep( 4 );
#endif
    }
    
    /* TPM_Extend the log that we just did */
    
    grub_uint8_t result[SHA1_DIGEST_SIZE] = { 0 };
    /* Do the TPM_Extend via a pass-through */
    grub_TPM_extendpcr(pcrIndex, inDigest, result);
    
#ifdef TGRUB_DEBUG
    DEBUG_PRINT( ( "TPM_Extend on PCR %u \n", pcrIndex ) );
    DEBUG_PRINT( ( "New PCR[%u]=", pcrIndex ) );
    print_sha1(result);
    DEBUG_PRINT( ( "\n\n" ) );
#endif    


    grub_free(event);
}

/************************* non-static functions *************************/

/* grub_fatal() on error */
void
grub_TPM_extendpcr(const grub_uint8_t index, const grub_uint8_t* inDigest, grub_uint8_t* result ) {

    CHECK_FOR_NULL_ARGUMENT( result )
    CHECK_FOR_NULL_ARGUMENT( inDigest )
    
    PassThroughToTPM_InputParamBlock *passThroughInput = NULL;
    PCRExtendIncoming* pcrExtendIncoming = NULL;
    grub_uint16_t inputlen = sizeof( *passThroughInput ) - sizeof( passThroughInput->TPMOperandIn ) + sizeof( *pcrExtendIncoming );

    PassThroughToTPM_OutputParamBlock *passThroughOutput = NULL;
    PCRExtendOutgoing* pcrExtendOutgoing = NULL;
    grub_uint16_t outputlen = sizeof( *passThroughOutput ) - sizeof( passThroughOutput->TPMOperandOut ) + sizeof( *pcrExtendOutgoing );

    passThroughInput = grub_zalloc( inputlen );
    if( ! passThroughInput ) {
        grub_fatal( "extendpcr: memory allocation failed" );
    }

    passThroughInput->IPBLength = inputlen;
    passThroughInput->OPBLength = outputlen;

    pcrExtendIncoming = (void*) passThroughInput->TPMOperandIn;
    pcrExtendIncoming->tag = grub_swap_bytes16_compile_time( TPM_TAG_RQU_COMMAND );
    pcrExtendIncoming->paramSize = grub_swap_bytes32( sizeof( *pcrExtendIncoming ) );
    pcrExtendIncoming->ordinal = grub_swap_bytes32_compile_time( TPM_ORD_Extend );
    pcrExtendIncoming->pcrIndex = grub_swap_bytes32( (grub_uint32_t) index);

    grub_memcpy(pcrExtendIncoming->inDigest, inDigest, SHA1_DIGEST_SIZE );
    
    passThroughOutput = grub_zalloc( outputlen );
    if( ! passThroughOutput ) {
        grub_free( passThroughInput );
        grub_fatal( "extendpcr: memory allocation failed" );
    }

    grub_TPM_int1A_passThroughToTPM( passThroughInput, passThroughOutput );
    grub_free( passThroughInput );

    pcrExtendOutgoing = (void *)passThroughOutput->TPMOperandOut;
    grub_uint32_t tpm_PCRextendReturnCode = grub_swap_bytes32( pcrExtendOutgoing->returnCode );

    if( tpm_PCRextendReturnCode != TPM_SUCCESS ) {
        grub_free( passThroughOutput );

        if( tpm_PCRextendReturnCode == TPM_BADINDEX ) {
            grub_fatal( "extendpcr: bad pcr index" );
        }

        grub_fatal( "extendpcr: tpm_PCRextendReturnCode: %u", tpm_PCRextendReturnCode );
    }

    grub_memcpy( result, pcrExtendOutgoing->pcr_value, SHA1_DIGEST_SIZE );
    grub_free( passThroughOutput );
}


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
grub_TPM_measure_string( const char* string, const grub_uint8_t index ) {

    CHECK_FOR_NULL_ARGUMENT( string )
#ifdef TGRUB_DEBUG
    grub_printf("string to measure: '%s'\n", string);
#endif
    /* measure with TPM_Extend if logging works, else fall back
     * to TCG_compactLogHashEvent.  Event logging is essential.
     */
    grub_TPM_hashExtendAndLogPCR(string, grub_strlen(string), index, string, 1);
 
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

    /* measure with the extend and log method */
    grub_TPM_extendAndLogPCR( convertedResult, index, filename );
}

void
grub_TPM_measure_buffer( const void* buffer, const grub_uint32_t bufferLen, const grub_uint8_t index ) {

    CHECK_FOR_NULL_ARGUMENT( buffer )
    
    /* measure with TPM_Extend, no fallback on logging */
    grub_TPM_hashExtendAndLogPCR(buffer, bufferLen, index, "buffer", 0);

}
/* End TCG Extension */
