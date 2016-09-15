AM_CPPFLAGS = @LIBGCRYPT_CFLAGS@

lib_LTLIBRARIES = libotr.la

libotr_la_SOURCES = privkey.c context.c proto.c b64.c dh.c mem.c message.c \
		    userstate.c tlv.c auth.c sm.c context_priv.c instag.c \
		    chat_attest.c chat_auth.c chat_communication.c chat_context.c chat_dake.c \
		    chat_dske.c chat_enc.c chat_event.c chat_fingerprint.c chat_idkey.c chat_info.c\
		    chat_message.c chat_offer.c chat_participant.c chat_pending.c \
		    chat_privkeydh.c chat_protocol.c chat_serial.c chat_shutdown.c \
		    chat_sign.c chat_token.c list.c tdh.c 

libotr_la_LDFLAGS = -version-info @LIBOTR_LIBTOOL_VERSION@ @LIBS@ @LIBGCRYPT_LIBS@

otrincdir = $(includedir)/libotr

otrinc_HEADERS = b64.h context.h dh.h mem.h message.h privkey.h proto.h \
		 version.h userstate.h tlv.h serial.h auth.h sm.h privkey-t.h \
		 context_priv.h instag.h \
		 chat_attest.h chat_auth.h chat_communication.h chat_context.h chat_dake.h chat_dske.h \
		 chat_enc.h chat_event.h chat_fingerprint.h chat_idkey.h chat_info.h chat_message.h chat_offer.h \
		 chat_participant.h chat_pending.h chat_privkeydh.h chat_protocol.h \
		 chat_serial.h chat_shutdown.h chat_sign.h chat_token.h chat_types.h list.h \
		 tdh.h
