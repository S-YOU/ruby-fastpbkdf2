#include <ruby.h>
#include "fastpbkdf2.h"

static VALUE fastpbkdf2;

#define DECL(ALGORITHM) \
static VALUE ALGORITHM(VALUE self, VALUE _pw, VALUE _salt, VALUE _iterations, VALUE _keylen) {\
	uint8_t *pw = NULL, *salt = NULL;\
	size_t npw, nsalt;\
	unsigned int iterations, keylen;\
	unsigned char out[2048];\
	VALUE result;\
\
	Check_Type(_pw, T_STRING);\
	pw = (uint8_t*) RSTRING_PTR(_pw);\
	npw = RSTRING_LEN(_pw);\
	if (npw > 1024) {\
		rb_raise(rb_eRangeError, "password length must be between 0 and 1024");\
	}\
\
	Check_Type(_salt, T_STRING);\
	salt = (uint8_t*) RSTRING_PTR(_salt);\
	nsalt = RSTRING_LEN(_salt);\
	if (nsalt > 1024) {\
		rb_raise(rb_eRangeError, "salt length must be between 0 and 1024");\
	}\
\
	Check_Type(_iterations, T_FIXNUM);\
	iterations = NUM2ULL(_iterations);\
	if (iterations <= 0) {\
		rb_raise(rb_eRangeError, "iterations must be greater than 0");\
	}\
\
	Check_Type(_keylen, T_FIXNUM);\
	keylen = NUM2ULL(_keylen);\
	if (keylen <= 0 || keylen > 1024) {\
		rb_raise(rb_eRangeError, "keylen must be between 1 and 1024");\
	}\
\
	fastpbkdf2_hmac_##ALGORITHM(pw, npw, salt, nsalt, iterations, out, keylen);\
\
	result = rb_str_new((char *)out, keylen);\
\
	return result;\
}

DECL(sha1)
DECL(sha256)
DECL(sha512)

void Init_fastpbkdf2_native(void) {
	fastpbkdf2 = rb_define_module("Fastpbkdf2");

	rb_define_module_function(fastpbkdf2, "sha1", sha1, 4);
	rb_define_module_function(fastpbkdf2, "sha256", sha256, 4);
	rb_define_module_function(fastpbkdf2, "sha512", sha512, 4);
}
