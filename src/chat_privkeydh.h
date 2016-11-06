/*
 *  Off-the-Record Messaging library
 *  Copyright (C) 2015-2016  Dimitrios Kolotouros <dim.kolotouros@gmail.com>,
 *  						 Konstantinos Andrikopoulos <el11151@mail.ntua.gr>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __PRIVKEYDH_H__
#define __PRIVKEYDH_H__

#include <stdio.h>
#include <gcrypt.h>
#include <sys/stat.h>

#include "dh.h"
#include "userstate.h"
#include "message.h"

#define CHAT_FINGERPRINT_SIZE 32

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

ChatIdKey * chat_privkeydh_find_or_generate(OtrlUserState us, const OtrlMessageAppOps *ops, const char *accountname, const char* protocol);

int chat_privkeydh_key_exists(OtrlUserState us, const char *accountname, const char *protocol);

unsigned char *chat_privkeydh_get_fingerprint(gcry_mpi_t pubkey);

#endif
