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

#ifndef CHAT_CONTEXT_H_
#define CHAT_CONTEXT_H_

#include "instag.h"
#include "context.h"
#include "dh.h"
#include "message.h"
//#include "chat_token.h"
//#include "chat_auth.h"
//#include "chat_enc.h"

#include "chat_types.h"

//typedef struct OtrlChatContextStruct {
//	/* Context information that is meant for application use */
//
//	char * accountname;                /* The username is relative to this account... */
//	char * protocol;                   /* ... and this protocol */
//	otrl_instag_t our_instance;        /* Our instance tag for this computer*/
//	otrl_chat_token_t the_chat_token;  /* The token of the chat */
//
//	Fingerprint fingerprint_root;      /* The root of a linked list of
//					      Fingerprints entries. This list will
//					      only be populated in master contexts.
//					      For child contexts,
//					      fingerprint_root.next will always
//					      point to NULL. */
//
//	OtrlChatEncInfo enc_info;              /* Info needed for encrypting messages */
//
//	OtrlAuthGKAInfo gka_info;          /* Info needed for the GKA */
//
//	OtrlMessageState msg_state;
//
//	Fingerprint *active_fingerprint;   /* Which fingerprint is in use now?
//					      A pointer into the above list */
//
//	unsigned char sessionid[20];       /* The sessionid and bold half */
//	size_t sessionid_len;              /* determined when this private */
//	OtrlSessionIdHalf sessionid_half;  /* connection was established. */
//
//	unsigned int protocol_version;     /* The version of OTR in use */
//
//	/* Application data to be associated with this context */
//	void *app_data;
//	/* A function to free the above data when we forget this context */
//	void (*app_data_free)(void *);
//} OtrlChatContext;

int chat_context_compare(PayloadPtr a, PayloadPtr b);

void chat_context_free(PayloadPtr a);

int chat_context_remove(OtrlUserState us, OtrlChatContext *ctx);

OtrlChatContext* chat_context_find(OtrlUserState us, const OtrlMessageAppOps *ops,
		const char *accountname, const char *protocol, otrl_chat_token_t the_chat_token);

int chat_context_add(OtrlUserState us, OtrlChatContext* ctx);

OtrlChatContext * chat_context_create(OtrlUserState us, const OtrlMessageAppOps *ops, const char *accountname, const char *protocol,
		otrl_chat_token_t the_chat_token);

OtrlChatContext* chat_context_find_or_add(OtrlUserState us, const OtrlMessageAppOps *ops,
		const char *accountname, const char *protocol, otrl_chat_token_t the_chat_token);

struct OtrlListOpsStruct chat_context_listOps;

void chat_context_toString(OtrlListNode *node);

#endif /* CHAT_CONTEXT_H_ */
