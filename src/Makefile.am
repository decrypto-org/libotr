AM_CPPFLAGS = @LIBGCRYPT_CFLAGS@

lib_LTLIBRARIES = libotr.la

libotr_la_SOURCES = privkey.c context.c proto.c b64.c dh.c mem.c message.c \
		    userstate.c tlv.c auth.c sm.c context_priv.c instag.c \
		    chat_auth.c chat_context.c chat_enc.c chat_idkey.c \
		    chat_message.c chat_participant.c chat_privkeydh.c \
		    chat_serial.c chat_token.c list.c 

libotr_la_LDFLAGS = -version-info @LIBOTR_LIBTOOL_VERSION@ @LIBS@ @LIBGCRYPT_LIBS@

otrincdir = $(includedir)/libotr

otrinc_HEADERS = b64.h context.h dh.h mem.h message.h privkey.h proto.h \
		 version.h userstate.h tlv.h serial.h auth.h sm.h privkey-t.h \
		 context_priv.h instag.h \
		 chat_auth.h chat_context.h chat_enc.h chat_idkey.h \
		 chat_message.h chat_participant.h chat_privkeydh.h \
		 chat_serial.h chat_token.h chat_types.h list.h 
