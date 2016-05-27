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

#include "userstate.h"
#include "stdio.h"

#define CHAT_FINGERPRINT_BUFSIZE 1024

typedef struct ChatFingerprintStruct {
	unsigned char *fingerprint;
	char *username;     /* the username that the fingerprint corresponds to */
	char *accountname;  /* the account name we have trusted with */
	char *protocol;		/* the protocol we have trusted the user with */
} ChatFingerprint;

char *chat_fingerprint_bytes_to_hex(const unsigned char *fingerprint);

ChatFingerprint *chat_fingerprint_find(OtrlUserState us, char *accountname , char *protocol, char *username);

int otrl_chat_fingerprint_read_FILEp(OtrlUserState us, FILE *fingerfile);

struct OtrlListOpsStruct chat_fingerprint_listOps;

#endif /* CHAT_FINGERPRINT_H_ */
