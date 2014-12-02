/* Begin TCG Extension */

#ifndef GRUB_SHA1_H
#define GRUB_SHA1_H	1

#define SHA1_DIGEST_SIZE 20

#define TCG_BUFFER_SIZE  4096

#include <grub/file.h>

/* Typedefs needed for the SHA1-implementation */
typedef unsigned int      t_U32;
typedef unsigned short     t_U16;
typedef unsigned char      t_U8;
typedef signed long        t_S32;
typedef signed short       t_S16;
typedef signed char        t_S8;
typedef char*              t_string;

/* Struct for SHA1-Context */
typedef struct
{
  t_U32 total_bytes_Hi; /* high word of 64-bit value for bytes count */
  t_U32 total_bytes_Lo; /* low word of 64-bit value for bytes count  */
  t_U32 vector[5];      /* 5  32-bit hash words                     */
  t_U8  buffer[64];     /* 64 byte buffer                            */
} sha1_context;

/* Creates SHA1-Hash of a file and stores digest in result */
grub_err_t sha1_hash_file( const grub_file_t file, void* result );

/* Creates SHA1-Hash of a string and stores digest in result */
grub_err_t sha1_hash_string( const char* string, void* result );

/* Creates SHA1-Hash of a buffer and stores digest in result */
grub_err_t sha1_hash_buffer( const void* buffer, const grub_uint32_t bufferLen, void* result );

#endif /* ! GRUB_SHA1_H */
/* End TCG Extension */
