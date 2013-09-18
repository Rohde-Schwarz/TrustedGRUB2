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

/* This is the correct include
#include <grub/machine/tpm_kern.h> */

/* only for better eclipse integration: */
#include <grub/i386/pc/tpm_kern.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_cmd_readpcr( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

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

	grub_TPM_readpcr( index );

	return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_tcglog( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

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

	grub_TPM_read_tcglog( index );

	return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_measure( grub_command_t cmd __attribute__ ((unused)), int argc, char **args) {

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

	if( grub_TPM_measureFile( args[0], index ) == GRUB_ERR_TPM) {
		return grub_error( GRUB_ERR_TPM, N_( "TPM not available" ) );
	}

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_tpmtest( grub_command_t cmd __attribute__ ((unused)), int argc __attribute__ ((unused)), char **args __attribute__ ((unused))) {
#if 0
	/*
	char a0[] = "1";
	char *argss[] = { a0, NULL };

	grub_command_t cmd_pcr = grub_command_find( "readpcr" );
	if( cmd_pcr ) {
		if( !(cmd_pcr->func) ( cmd, 1, argss ) ) {
		}
	}*/

	GRUB_PROPERLY_ALIGNED_ARRAY( fingerprint_context, GRUB_MD_SHA1->contextsize );
	grub_memset( fingerprint_context, 0, sizeof( fingerprint_context ) );
	GRUB_MD_SHA1->init( fingerprint_context );
	GRUB_MD_SHA1->write( fingerprint_context, "\x99", 1 );
	GRUB_MD_SHA1->final( fingerprint_context );

	grub_uint8_t hash[SHA1_DIGEST_SIZE];

	grub_memcpy( hash, GRUB_MD_SHA1->read( fingerprint_context ), 20 );

	/* print_sha1( hash ); */
#endif

  return GRUB_ERR_NONE;
}

static grub_command_t cmd_readpcr, cmd_tcglog, cmd_measure, cmd_tpmtest;

GRUB_MOD_INIT(tpm)
{
	cmd_readpcr = grub_register_command( "readpcr", grub_cmd_readpcr, N_( "pcrindex" ),
  		N_( "Display current value of the PCR (Platform Configuration Register) within "
  		    "TPM(Trusted Platform Module) at index, pcrindex." ) );

	cmd_tcglog = grub_register_command( "tcglog", grub_cmd_tcglog, N_( "logindex" ),
		N_( "Displays TCG event log entry at position, logindex." ) );

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
