#ifndef __PRIVKEYDH_H__
#define __PRIVKEYDH_H__

#include <stdio.h>
#include <gcrypt.h>
#include <sys/stat.h>

#include "dh.h"
#include "userstate.h"

/*
 * Read a triple DH long term key from file privf
 */
gcry_error_t otrl_chat_privkeydh_read_FILEp(OtrlUserState us, FILE *privf);

/**
 * Generates a triple DH long term key for user accountname and protocol protocol
 *
 * @param us the user state passed by the plugin
 * @param privf the file where the long term keys are stored
 * @param accountname the accountname this key is generated for
 * @param protocol the protocol this account uses
 *
 * @return Zero on success. Non zero otherwise.
 */
int otrl_chat_privkeydh_generate_FILEp(OtrlUserState us, FILE *privf,
                                       const char *accountname,
                                       const char *protocol);

int chat_privkeydh_key_exists(OtrlUserState us, const char *accountname, const char *protocol);

#endif
