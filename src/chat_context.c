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

#include <stdlib.h>
#include <string.h>
#include "chat_context.h"
#include "userstate.h"
#include "list.h"
#include "chat_token.h"
#include "chat_participant.h"

int chat_context_compare(PayloadPtr a, PayloadPtr b)
{
	OtrlChatContext *a1 = (OtrlChatContext *)a;
	OtrlChatContext *b1 = (OtrlChatContext *)b;
	int res = 0;

	res = strcmp(a1->accountname, b1->accountname);
	if(res == 0) {
		res = strcmp(a1->protocol, b1->protocol);
		if(res == 0) {
			res = chat_token_compare(a1->the_chat_token, b1->the_chat_token);
		}
	}

	return res;
}


void chat_context_free(PayloadPtr a)
{
	OtrlChatContext *a1 = (OtrlChatContext *)a;
	if(a1) {
		if(a1->accountname) {
			free(a1->accountname);
		}
		// TODO Dimitris: maybe define enc_info as a pointer, and change this
		if(a1->enc_info.key) {
			free(a1->enc_info.key);
		}
		if(a1->protocol) {
			free(a1->protocol);
		}
		if(a1->app_data && a1->app_data_free) {
			a1->app_data_free(a1->app_data);
		}
		free(a1);
	}
}

OtrlChatContext* chat_context_find(OtrlUserState us,
		const char *accountname, const char *protocol, otrl_chat_token_t the_chat_token)
{
	OtrlListNode *foundListNode;
	OtrlChatContext *target;

	target = chat_context_create(us, accountname, protocol, the_chat_token);
	if(!target)
		return NULL;

	foundListNode = otrl_list_find(us->chat_context_list, (PayloadPtr)target);
	chat_context_free((PayloadPtr)target);

	if(!foundListNode)
		return NULL;

	return (OtrlChatContext *)foundListNode->payload;
}

int chat_context_add(OtrlUserState us, OtrlChatContext* ctx)
{
	OtrlListNode * aNode;

	aNode = otrl_list_insert(us->chat_context_list, (PayloadPtr)ctx);

	if(!aNode)
		return 1;
	else
		return 0;
}

OtrlChatContext * chat_context_create(OtrlUserState us, const char *accountname, const char *protocol,
		otrl_chat_token_t the_chat_token)
{
	OtrlChatContext *ctx;
	OtrlInsTag *ourInstanceTag;

	//TODO initialize other Context elements
	ctx = (OtrlChatContext *)malloc(sizeof(OtrlChatContext));
	if(ctx) {
		ctx->accountname = strdup(accountname);
		ctx->protocol = strdup(protocol);
		// TODO: Dimitris: Check what is returned here?
		// TODO: Dimitris: Important! We should handle the case of not found instag, and create a new one!!!!
		ourInstanceTag = otrl_instag_find(us, accountname, protocol);
		if(!ourInstanceTag) {
			fprintf(stderr, "libotr-mpOTR: chat_context_create: ourInstanceTag not found!\n");
		}
		ctx->our_instance = ourInstanceTag->instag;
		ctx->the_chat_token = the_chat_token;
		ctx->participants_list = otrl_list_init(&chat_participant_listOps, sizeof(OtrlChatParticipant));
		ctx->gka_info.auth_msg = NULL;
		ctx->gka_info.keypair = NULL;
		ctx->gka_info.state = OTRL_CHAT_GKASTATE_NONE;
		ctx->msg_state = OTRL_MSGSTATE_PLAINTEXT;
		ctx->protocol_version = CHAT_PROTOCOL_VERSION;
		// TODO Dimitris: maybe define enc_info as a pointer, and change this
		ctx->enc_info.key = NULL;
		ctx->app_data = NULL;
		ctx->app_data_free = NULL;
	}

	return ctx;
}

OtrlChatContext* chat_context_find_or_add(OtrlUserState us,
		const char *accountname, const char *protocol, otrl_chat_token_t the_chat_token)
{
	OtrlChatContext *ctx;

	ctx = chat_context_find(us, accountname, protocol, the_chat_token);

	if(!ctx) {
		ctx = chat_context_create(us, accountname, protocol, the_chat_token);
		if(ctx) {
			if (chat_context_add(us, ctx)) {
				chat_context_free((PayloadPtr)ctx);
				ctx = NULL;
			}
		}
	}

	return ctx;
}

struct OtrlListOpsStruct chat_context_listOps = {
		chat_context_compare,
		chat_context_toString,
		chat_context_free
};

void chat_context_toString(OtrlListNode *node) {
	OtrlChatContext *ctx = (OtrlChatContext *)(node->payload);
	fprintf(stderr, "OtrlChatContext:\n");
	fprintf(stderr, "|-accountname   : %s\n", ctx->accountname);
	fprintf(stderr, "|-protocol      : %s\n", ctx->protocol);
	fprintf(stderr, "|-our_instance  : %d\n", (int)ctx->our_instance);
	// TODO change the way we typecast the_chat_token
	fprintf(stderr, "|-the_chat_token: %d\n", *((int *)ctx->the_chat_token));
}
