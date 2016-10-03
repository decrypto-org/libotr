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

#ifndef CHAT_FINGERPRINT_H_
#define CHAT_FINGERPRINT_H_

#include <stdio.h>

#include "list.h"

#define CHAT_FINGERPRINT_BUFSIZE 1024

typedef struct OtrlChatFingerprintStruct * OtrlChatFingerprint;

char *otrl_chat_fingerprint_bytes_to_hex(const unsigned char *fingerprint);
size_t chat_fingerprint_size();
OtrlChatFingerprint chat_fingerprint_new(char *accountname, char *protocol, char *username, unsigned char *bytes, int isTrusted);
void chat_fingerprint_free(OtrlChatFingerprint fnprnt);
char * otrl_chat_fingerprint_get_accountname(OtrlChatFingerprint fnprnt);
char * otrl_chat_fingerprint_get_protocol(OtrlChatFingerprint fnprnt);
char * otrl_chat_fingerprint_get_username(OtrlChatFingerprint fnprnt);
unsigned char * otrl_chat_fingerprint_get_bytes(OtrlChatFingerprint fnprnt);
int otrl_chat_fingerprint_is_trusted(OtrlChatFingerprint fnprnt);
OtrlChatFingerprint chat_fingerprint_find(OtrlList fingerlist, char *accountname , char *protocol, char *username, unsigned char *bytes);
int chat_fingerprint_add(OtrlList fingerlist, OtrlChatFingerprint fnprnt);
int chat_fingerprint_remove(OtrlList fingerlist, OtrlChatFingerprint fnprnt);
void chat_fingerprint_verify(OtrlChatFingerprint fnprnt);
void chat_fingerprint_forget(OtrlList fingerlist, OtrlChatFingerprint fnprnt);
int chat_fingerprint_read_FILEp(OtrlList fingerlist, FILE *fingerfile);
int chat_fingerprint_write_FILEp(OtrlList fingerlist, FILE *fingerFile);

struct OtrlListOpsStruct chat_fingerprint_listOps;

#endif /* CHAT_FINGERPRINT_H_ */
