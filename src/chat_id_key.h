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

#ifndef CHAT_ID_KEY_H_
#define CHAT_ID_KEY_H_

#define CHAT_ID_KEY_FINGERPRINT_SIZE 32

#include <gcrypt.h>

#include "list.h"

typedef void * ChatInternalKeyPtr;
typedef struct ChatInternalKeyOps * ChatInternalKeyOpsPtr;

struct ChatInternalKeyOps{
    ChatInternalKeyPtr (*generate)(void);
    int (*serialize)(ChatInternalKeyPtr, gcry_sexp_t *);
    ChatInternalKeyPtr (*parse)(gcry_sexp_t);
    unsigned char * (*fingerprint_create)(ChatInternalKeyPtr);
    void (*free)(ChatInternalKeyPtr);
};

typedef struct ChatIdKeyS * ChatIdKeyPtr;

size_t chat_id_key_size();

char * chat_id_key_get_accountname(ChatIdKeyPtr key);
char * chat_id_key_get_protocol(ChatIdKeyPtr key);
ChatInternalKeyPtr chat_id_key_get_internal_key(ChatIdKeyPtr key);
unsigned char * chat_id_key_fingerprint_create(ChatIdKeyPtr key);
int chat_id_key_find(OtrlListPtr key_list, const char * accountname, const char *protocol, ChatIdKeyPtr *found);
int chat_id_key_generate_new(OtrlListPtr key_list, const char *accountname, const char *protocol, ChatInternalKeyOpsPtr internal_key_ops);
int chat_id_key_list_read_FILEp(OtrlListPtr key_list, ChatInternalKeyOpsPtr internal_key_ops, FILE *privf);
int chat_id_key_list_write_FILEp(OtrlListPtr key_list, FILE *privf);

struct OtrlListOpsStruct chat_id_key_listOps;

OtrlListPtr chat_id_key_info_list_create(OtrlListPtr key_list);

#endif /* CHAT_ID_KEY_H_ */
