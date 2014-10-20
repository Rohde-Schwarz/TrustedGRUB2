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

#include <grub/machine/tpm_kern.h>
#include <grub/machine/boot.h>

GRUB_MOD_LICENSE ("GPLv3+");

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

	unsigned char nonceEven[TPM_NONCE_SIZE];
	grub_uint32_t authHandle = 0;

	if( grub_TPM_openOIAP_Session( &authHandle, &nonceEven[0] ) == 0 ) {
		grub_printf( "open OIAP session failed\n" );
		return GRUB_ERR_NONE;
	}

	grub_printf( "nonceEven: " );
	unsigned int j;
	for( j = 0; j < TPM_NONCE_SIZE; ++j ) {
		grub_printf( "%02x", nonceEven[j] );
	}

	grub_printf( "\n authHandle: %x \n", authHandle );

	return GRUB_ERR_NONE;
}
#endif

static grub_command_t cmd_readpcr, cmd_tcglog, cmd_measure, cmd_setMOR;

#ifdef TGRUB_DEBUG
	static grub_command_t cmd_random, cmd_oiap;
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

#ifdef TGRUB_DEBUG
	cmd_random = grub_register_command( "random", grub_cmd_getRandom, N_( "bytesRequested" ),
			  	N_( "Gets random bytes from TPM." ) );
	cmd_oiap = grub_register_command( "oiap", grub_cmd_openOIAP, 0,
				  	N_( "Opens OIAP Session" ) );
#endif

}

GRUB_MOD_FINI(tpm)
{
	grub_unregister_command( cmd_readpcr );
	grub_unregister_command( cmd_tcglog );
	grub_unregister_command( cmd_measure );
	grub_unregister_command( cmd_setMOR );

#ifdef TGRUB_DEBUG
	grub_unregister_command( cmd_random );
	grub_unregister_command( cmd_oiap );
#endif

}

/* End TCG extension */
