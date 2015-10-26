require 'mkmf'

$CFLAGS += " -Wno-deprecated-declarations -std=c99 -O3 -g -Wall -pedantic"
$LOCAL_LIBS += " -lcrypto"

extension_name = "fastpbkdf2_native"

dir_config(extension_name)
create_makefile(extension_name)
