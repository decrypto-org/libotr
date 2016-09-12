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

#ifndef CHAT_IDKEY_H
#define CHAT_IDKEY_H

#include "list.h"

typedef struct {
	DH_keypair keyp;
	char* accountname;
	char* protocol;
} ChatIdKey;

typedef struct {
	void (*init)(ChatIdKey*);
	void (*destroy_key)(ChatIdKey*);
	ChatIdKey * (*parse)(gcry_sexp_t);
	int (*generate_key)(ChatIdKey**);
	gcry_error_t (*serialize)(ChatIdKey*, gcry_sexp_t*);
	ChatIdKey * (*find_key)(OtrlList *key_list, const char *accountname, const char *protocol);
} ChatIdKeyManager;

struct OtrlListOpsStruct chat_idkey_listOps;

ChatIdKeyManager chat_id_key_manager;

void chat_idkey_print(ChatIdKey *key);

ChatIdKey * chat_idkey_find(OtrlList *key_list, const char *accountname, const char *protocol);
#endif /* CHAT_IDKEY_H */
