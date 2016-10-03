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

#include "stdio.h"
#include "userstate.h"
#include "message.h"

#define CHAT_FINGERPRINT_BUFSIZE 1024

char *otrl_chat_fingerprint_bytes_to_hex(const unsigned char *fingerprint);

ChatFingerprint *chat_fingerprint_find(OtrlUserState us, char *accountname , char *protocol, char *username, unsigned char *fingerprint);

ChatFingerprint *chat_fingerprint_new(char *accountname, char *protocol, char *username, unsigned char *fingerprint, unsigned char isTrusted);

void chat_fingerprint_destroy(ChatFingerprint *fingerprint);

int chat_fingerprint_add(OtrlUserState us, ChatFingerprint *finger);

int otrl_chat_fingerprint_verify(OtrlUserState us, const OtrlMessageAppOps *ops, ChatFingerprint *finger);

int otrl_chat_fingerprint_forget(OtrlUserState us, const OtrlMessageAppOps *ops, ChatFingerprint *finger);

int otrl_chat_fingerprint_read_FILEp(OtrlUserState us, FILE *fingerfile);

int otrl_chat_fingerprint_write_FILEp(OtrlUserState us, FILE *fingerFile);

struct OtrlListOpsStruct chat_fingerprint_listOps;

#endif /* CHAT_FINGERPRINT_H_ */
