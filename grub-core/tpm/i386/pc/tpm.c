/* Begin TCG extension */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>

/* This is the correct include
#include <grub/machine/tpm.h>
#include <grub/machine/memory.h>
*/

/* only for eclipse: */
#include <grub/i386/pc/tpm.h>
#include <grub/i386/pc/memory.h>

#include <grub/file.h>
#include <grub/crypto.h>

GRUB_MOD_LICENSE ("GPLv3+");

static void
print_sha1( grub_uint8_t *inDigest ) {

	/* print SHA1 hash of input file */
	unsigned int j;
	for( j = 0; j < SHA1_DIGEST_SIZE; j++ ) {
		grub_printf( "%02x", inDigest[j] );
	}
}

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

/* FIXME: find out how to call this function directly */
/* From grub-core/commands/hashsum.c  */
static grub_err_t
hash_file( grub_file_t file, const gcry_md_spec_t *hash, void *result ) {
  grub_uint8_t context[hash->contextsize];
  grub_uint8_t readbuf[4096];

  grub_memset( context, 0, sizeof( context ) );
  hash->init( context );
  while( 1 ) {
      grub_ssize_t r;
      r = grub_file_read( file, readbuf, sizeof( readbuf ) );
      if( r < 0 ) {
    	  return grub_errno;
      }
      if( r == 0 ) {
    	  break;
      }
      hash->write( context, readbuf, r );
  }
  hash->final( context );
  grub_memcpy( result, hash->read( context ), hash->mdlen );

  return GRUB_ERR_NONE;
}


/* Invokes assembler function asm_tcg_statusCheck()

   Return value = 1 if function successfully completed and TPM is available
   Further returnvalues:
   returnCode
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
	grub_memcpy( p, input, input->IPBLength );
	grub_unmap_memory( p, input->IPBLength );

	/*  grub_printf( "input->IPBLength: %x\n", input->IPBLength );
		grub_printf( "input->OPBLength: %x\n", input->OPBLength );
		grub_printf( "input->Reserved1: %x\n", input->Reserved1 );
		grub_printf( "input->Reserved2: %x\n", input->Reserved2 );
		grub_printf( "input->TPMOperandIn: %x\n", *input->TPMOperandIn ); */

	/* 	tpmInput = (void *)input->TPMOperandIn;
		grub_printf( "tpminput->tag: %x\n", tpmInput->tag );
		grub_printf( "tpminput->len: %x\n", tpmInput->len );
		grub_printf( "tpminput->command: %x\n", tpmInput->command );
		grub_printf( "tpminput->bytessize: %x\n", tpmInput->bytessize ); */

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
	grub_memcpy( output, p, input->OPBLength );
	grub_unmap_memory( p, input->OPBLength );

	/* FIXME
	   output->OPBLength has to be the same as input->OPBLength
	   But they are not ?!
	   output->Reserved has to be zero. But it is not. */

	/* grub_printf( "%x\n", output->OPBLength ); */
	/* grub_printf( "%x\n", output->Reserved ); */
	return 1;
}

static unsigned int grubTPM_AvailabilityAlreadyChecked = 0;
static unsigned int grubTPM_isAvailable = 0;

grub_uint32_t
grub_TPM_isAvailable( void ) {

	/* Checking for availability takes a while. so its useful to check this only once */
	if( grubTPM_AvailabilityAlreadyChecked ) {
		return grubTPM_isAvailable;
	}

	grub_uint32_t returnCode, featureFlags, eventLog, edi, statusCheckReturn;
	grub_uint8_t major, minor;

	/* FIXME: do something with returnCode?! */
	statusCheckReturn = tcg_statusCheck( &returnCode, &major, &minor, &featureFlags, &eventLog, &edi );

	grubTPM_AvailabilityAlreadyChecked = 1;

	if ( statusCheckReturn == 1 ) {
		/* tpm available */
		grubTPM_isAvailable = 1;
	}

	return grubTPM_isAvailable;
}

static grub_err_t
grub_cmd_readpcr( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

	if( !grub_TPM_isAvailable() ) {
		return grub_error( GRUB_ERR_TPM, N_( "TPM not available" ) );
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
		return 0;
	}

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
	output = grub_zalloc( outputlen );
	input->IPBLength = inputlen;
	input->OPBLength = outputlen;

	tpmInput = (void *)input->TPMOperandIn;
	tpmInput->tag = swap16( TPM_TAG_RQU_COMMAND );
	tpmInput->paramSize = swap32( sizeof( *tpmInput ) );
	tpmInput->ordinal = swap32( TPM_ORD_PcrRead );
	tpmInput->pcrIndex = swap32( index );

	/* FIXME: do something with passThroughTo_TPM_ReturnCode */
	grub_uint32_t passThroughTo_TPM_ReturnCode;
	if( tcg_passThroughToTPM( input, output, &passThroughTo_TPM_ReturnCode ) == 0 ) {
		grub_free( input );
		grub_free( output );
		return grub_error( GRUB_ERR_TPM, N_( "PCR read failed" ) );
	}

	tpmOutput = (void *)output->TPMOperandOut;
	grub_uint32_t tpm_PCRreadReturnCode = swap32( tpmOutput->returnCode );

	if( tpm_PCRreadReturnCode != TPM_SUCCESS ) {
		grub_free( input );
		grub_free( output );

		if( tpm_PCRreadReturnCode == TPM_BADINDEX ) {
			return grub_error( GRUB_ERR_TPM, N_( "Bad PCR index" ) );
		}
		return grub_error( GRUB_ERR_TPM, N_( "PCR read failed" ) );
	}

	grub_free( input );
	grub_free( output );

	grub_printf( "PCR[%lu]=", index );
	print_sha1( tpmOutput->pcr_value );
	grub_printf("\n");

	return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_tcglog( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

	if( !grub_TPM_isAvailable() ) {
		return grub_error( GRUB_ERR_TPM, N_( "TPM not available" ) );
	}

	if ( argc > 1 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Too many arguments" ) );
	}

	grub_uint32_t returnCode, featureFlags, eventLog = 0, logAddr = 0, edi = 0, i;
	grub_uint8_t major, minor;
	tcg_statusCheck( &returnCode, &major, &minor, &featureFlags, &eventLog, &edi );

	/* edi = 0 means event log is empty */
	if( edi == 0 ) {
		return grub_error( GRUB_ERR_TPM, N_( "Event log empty" ) );
	}

	logAddr = eventLog;
	TCG_PCClientPCREvent *event;
	/* no argument == print all entries */
	if ( argc == 0 ) {

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
		unsigned long index = grub_strtoul( args[0], NULL, 10 );
		if( index <= 0 ) {
			return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Index must be greater than 0" ) );
		}

		logAddr = eventLog;

		for( i = 1; i < index; i++ ) {
			event = (TCG_PCClientPCREvent *)logAddr;
			logAddr += TCG_PCR_EVENT_SIZE + event->eventDataSize;

			if( logAddr > edi ) { /* index not valid.  */
				return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "logentry nonexistent" ) );
			}
		}

		event = (TCG_PCClientPCREvent *)logAddr;
		grub_printf( "pcrIndex: %x \n", event->pcrIndex );
		grub_printf( "eventType: %x \n", event->eventType );
		grub_printf( "digest: " );
		print_sha1( event->digest );
		grub_printf( "\n\n" );
	}
  return GRUB_ERR_NONE;
}

grub_err_t
grub_TPM_measureString( char *string ) {

	if( !grub_TPM_isAvailable() ) {
		return 0;
	}

	if ( string == 0 ) {
		return grub_error( GRUB_ERR_TPM, N_( "Measurement failed" ) );
	}

	unsigned long index = 12;

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

	/* FIXME: Why is this Offset value (+47) needed? */
	grub_uint32_t outputlen = sizeof( *output ) - sizeof( output->TPMOperandOut ) + sizeof( *tpmOutput ) + 64 ;

	input = grub_zalloc( inputlen );
	output = grub_zalloc( outputlen );
	input->IPBLength = inputlen;
	input->OPBLength = outputlen;

	tpmInput = (void *)input->TPMOperandIn;
	tpmInput->tag = swap16( TPM_TAG_RQU_COMMAND );
	tpmInput->paramSize = swap32( sizeof( *tpmInput ) );
	tpmInput->ordinal = swap32( TPM_ORD_Extend );
	tpmInput->pcrNum = swap32( index );

	const gcry_md_spec_t *hash = grub_crypto_lookup_md_by_name("sha1");

	/* hash string */
	grub_uint8_t context[hash->contextsize];
	grub_memset( context, 0, sizeof( context ) );
	hash->init( context );
	hash->write( context, string, grub_strlen( string ) );
	hash->final( context );
	grub_memcpy( tpmInput->inDigest, hash->read( context ), hash->mdlen );

	/* print SHA1 hash of input string */
	/*
	unsigned int j;
	for( j = 0; j < SHA1_DIGEST_SIZE; j++ ) {
		grub_printf( "%02x", tpmInput->inDigest[j] );
	}
	grub_printf( "  %s\n", string ); */

	/* FIXME: do something with passThroughTo_TPM_ReturnCode */
	grub_uint32_t passThrough_TPM_ReturnCode;
	if( tcg_passThroughToTPM( input, output, &passThrough_TPM_ReturnCode ) == 0 ) {
		grub_free( input );
		grub_free( output );
		return grub_error( GRUB_ERR_TPM, N_( "Measurement failed" ) );
	}

	tpmOutput = (void *)output->TPMOperandOut;
	grub_uint32_t tpmExtendReturnCode = swap32( tpmOutput->returnCode );

	if( tpmExtendReturnCode != TPM_SUCCESS ) {
		grub_free( input );
		grub_free( output );

		if( tpmExtendReturnCode == TPM_BADINDEX ) {
			return grub_error( GRUB_ERR_TPM, N_( "Bad PCR index" ) );
		}

		return grub_error( GRUB_ERR_TPM, N_( "Measurement failed" ) );
	}

	grub_free( input );
	grub_free( output );

	/*
	grub_printf( "New PCR[%lu]=", index );
	print_sha1( tpmOutput->outDigest );
	grub_printf("\n");*/

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_measure( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

	if( !grub_TPM_isAvailable() ) {
		return grub_error( GRUB_ERR_TPM, N_( "TPM not available" ) );
	}

	if ( argc != 2 ) {
		return grub_error( GRUB_ERR_BAD_ARGUMENT, N_( "Wrong number of arguments" ) );
	}

	unsigned long index = grub_strtoul( args[1], NULL, 10 );

	/* if index is invalid */
	if( grub_errno != GRUB_ERR_NONE ) {
		grub_print_error();
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}

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

	/* FIXME: Why is this Offset value (+47) needed? */
	grub_uint32_t outputlen = sizeof( *output ) - sizeof( output->TPMOperandOut ) + sizeof( *tpmOutput ) + 64 ;

	input = grub_zalloc( inputlen );
	output = grub_zalloc( outputlen );
	input->IPBLength = inputlen;
	input->OPBLength = outputlen;

	tpmInput = (void *)input->TPMOperandIn;
	tpmInput->tag = swap16( TPM_TAG_RQU_COMMAND );
	tpmInput->paramSize = swap32( sizeof( *tpmInput ) );
	tpmInput->ordinal = swap32( TPM_ORD_Extend );
	tpmInput->pcrNum = swap32( index );

	/* Open file and create sha1 hash */
	grub_file_t file = grub_file_open( args[0] );
	if( !file ) {
		grub_print_error();
		grub_errno = GRUB_ERR_NONE;
		grub_free( input );
		grub_free( output );
		return 0;
	}

	const gcry_md_spec_t *hash = grub_crypto_lookup_md_by_name("sha1");
	if( hash_file( file, hash, tpmInput->inDigest ) ) {
		grub_print_error();
		grub_errno = GRUB_ERR_NONE;
		grub_free( input );
		grub_free( output );
		return 0;
	}

	grub_file_close (file);

	/* print SHA1 hash of input file */
	unsigned int j;
	for( j = 0; j < SHA1_DIGEST_SIZE; j++ ) {
		grub_printf( "%02x", tpmInput->inDigest[j] );
	}
	grub_printf( "  %s\n", args[0] );

	/* FIXME: do something with passThroughTo_TPM_ReturnCode */
	grub_uint32_t passThrough_TPM_ReturnCode;
	if( tcg_passThroughToTPM( input, output, &passThrough_TPM_ReturnCode ) == 0 ) {
		grub_free( input );
		grub_free( output );
		return grub_error( GRUB_ERR_TPM, N_( "Measurement failed" ) );
	}

	tpmOutput = (void *)output->TPMOperandOut;
	grub_uint32_t tpmExtendReturnCode = swap32( tpmOutput->returnCode );

	if( tpmExtendReturnCode != TPM_SUCCESS ) {
		grub_free( input );
		grub_free( output );

		if( tpmExtendReturnCode == TPM_BADINDEX ) {
			return grub_error( GRUB_ERR_TPM, N_( "Bad PCR index" ) );
		}

		return grub_error( GRUB_ERR_TPM, N_( "Measurement failed" ) );
	}

	grub_free( input );
	grub_free( output );

	grub_printf( "New PCR[%lu]=", index );
	print_sha1( tpmOutput->outDigest );
	grub_printf("\n");

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_tpmtest( grub_command_t cmd __attribute__ ((unused)), int argc __attribute__ ((unused)), char **args __attribute__ ((unused))) {

	/*
	char a0[] = "1";
	char *argss[] = { a0, NULL };

	grub_command_t cmd_pcr = grub_command_find( "readpcr" );
	if( cmd_pcr ) {
		if( !(cmd_pcr->func) ( cmd, 1, argss ) ) {
		}
	}*/

	GRUB_PROPERLY_ALIGNED_ARRAY (fingerprint_context, GRUB_MD_SHA1->contextsize);
	grub_memset (fingerprint_context, 0, sizeof (fingerprint_context));
	GRUB_MD_SHA1->init (fingerprint_context);
	GRUB_MD_SHA1->write (fingerprint_context, "\x99", 1);
	GRUB_MD_SHA1->final (fingerprint_context);

  return GRUB_ERR_NONE;
}

static grub_command_t cmd_readpcr, cmd_tcglog, cmd_measure, cmd_tpmtest;

GRUB_MOD_INIT(tpm)
{
	cmd_readpcr = grub_register_command( "readpcr", grub_cmd_readpcr, N_( "pcrindex" ),
  		N_( "Display current value of the PCR (Platform Configuration Register) within "
  		    "TPM(Trusted Platform Module) at index, pcrindex." ) );

	cmd_tcglog = grub_register_command( "tcglog", grub_cmd_tcglog, N_( "[logindex]" ),
		N_( "Displays TCG event log entry at position, logindex. If no logindex is specified all entries will be printed" ) );

	cmd_measure = grub_register_command( "measure", grub_cmd_measure, N_( "FILE pcrindex" ),
	  	N_( "Perform TCG measurement operation with the file FILE and with PCR(pcrindex)." ) );

	cmd_tpmtest = grub_register_command( "tpmtest", grub_cmd_tpmtest, NULL,
		N_( "blabla" ) );
}

GRUB_MOD_FINI(tpm)
{
	grub_unregister_command( cmd_readpcr );
	grub_unregister_command( cmd_tcglog );
	grub_unregister_command( cmd_measure );
	grub_unregister_command( cmd_tpmtest );
}

/* End TCG extension */
