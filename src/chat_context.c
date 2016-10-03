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

int chat_context_compare(PayloadPtr a, PayloadPtr b)
{
	fprintf(stderr, "libotr-mpOTR: chat_context_compare: start\n");
	OtrlChatContext *a1 = (OtrlChatContext *)a;
	OtrlChatContext *b1 = (OtrlChatContext *)b;
	int res = 0;

	fprintf(stderr, "libotr-mpOTR: chat_context_compare: before strcmp(a1->accountname, b1->accountname);\n");
	res = strcmp(a1->accountname, b1->accountname);
	if(res == 0) {
		fprintf(stderr, "libotr-mpOTR: chat_context_compare: before res = strcmp(a1->protocol, b1->protocol);\n");
		res = strcmp(a1->protocol, b1->protocol);
		if(res == 0) {
			fprintf(stderr, "libotr-mpOTR: chat_context_compare: before chat_token_compare(a1->the_chat_token, b1->the_chat_token);\n");
			res = chat_token_compare(a1->the_chat_token, b1->the_chat_token);
		}
	}

	fprintf(stderr, "libotr-mpOTR: chat_context_compare: end\n");
	return res;
}


void chat_context_destroy(PayloadPtr a)
{
	fprintf(stderr, "libotr-mpOTR: chat_context_destroy: start\n");

	OtrlChatContext *a1 = (OtrlChatContext *)a;
	if(a1) {
		if(a1->accountname)
			fprintf(stderr, "libotr-mpOTR: chat_context_destroy: before free(a1->accountname);\n");
			free(a1->accountname);
		if(a1->protocol)
			fprintf(stderr, "libotr-mpOTR: chat_context_destroy: before free(a1->protocol);\n");
			free(a1->protocol);

		if(a1->app_data && a1->app_data_free) {
			fprintf(stderr, "libotr-mpOTR: chat_context_destroy: before a1->app_data_free(a1->app_data);\n");
			a1->app_data_free(a1->app_data);
		}

	}
}

OtrlChatContext* chat_context_find(OtrlUserState us,
		const char *accountname, const char *protocol, otrl_chat_token_t the_chat_token)
{
	OtrlListNode *foundListNode;
	OtrlChatContext *target;

	fprintf(stderr, "libotr-mpOTR: chat_context_find: start\n");


	fprintf(stderr, "libotr-mpOTR: chat_context_find: initializing target\n");
	target = chat_context_create(us, accountname, protocol, the_chat_token);
	if(!target)
		return NULL;

	fprintf(stderr, "libotr-mpOTR: chat_context_find: before otrl_list_find\n");
	foundListNode = otrl_list_find(us->chat_context_list, (PayloadPtr)target);
	fprintf(stderr, "libotr-mpOTR: chat_context_find: before chat_context_destroy\n");
	chat_context_destroy((PayloadPtr)target);

	if(!foundListNode)
		return NULL;

	fprintf(stderr, "libotr-mpOTR: chat_context_find: end\n");
	return (OtrlChatContext *)foundListNode->payload;
}

int chat_context_add(OtrlUserState us, OtrlChatContext* ctx)
{
	fprintf(stderr, "libotr-mpOTR: chat_context_add: start\n");

	OtrlListNode * aNode;
	fprintf(stderr, "libotr-mpOTR: chat_context_add: before otrl_list_insert\n");
	aNode = otrl_list_insert(us->chat_context_list, (PayloadPtr)ctx);

	fprintf(stderr, "libotr-mpOTR: chat_context_add: end\n");
	if(!aNode)
		return -1;
	else
		return 1;
}

OtrlChatContext * chat_context_create(OtrlUserState us, const char *accountname, const char *protocol,
		otrl_chat_token_t the_chat_token)
{
	OtrlChatContext *ctx;
	OtrlInsTag *ourInstanceTag;

	//TODO initialize other Context elements

	fprintf(stderr, "libotr-mpOTR: chat_context_create: before malloc\n");
	ctx = (OtrlChatContext *)malloc(sizeof(OtrlChatContext));
	if(ctx) {
		ctx->accountname = strdup(accountname);
		ctx->protocol = strdup(protocol);
		// TODO: Dimitris: Check what is returned here?
		fprintf(stderr, "libotr-mpOTR: chat_context_create: before otrl_instag_find, accountname: %s, protocol: %s\n", accountname, protocol);
		ourInstanceTag = otrl_instag_find(us, accountname, protocol);
		if(!ourInstanceTag) {
			fprintf(stderr, "libotr-mpOTR: chat_context_create: ourInstanceTag not found!\n");
		}
		ctx->our_instance = ourInstanceTag->instag;
		ctx->the_chat_token = the_chat_token;
		ctx->msg_state = OTRL_MSGSTATE_PLAINTEXT;
		ctx->protocol_version = CHAT_PROTOCOL_VERSION;
		ctx->app_data = NULL;
		ctx->app_data_free = NULL;
	}

	fprintf(stderr, "libotr-mpOTR: chat_context_create: end\n");
	return ctx;
}

OtrlChatContext* chat_context_find_or_add(OtrlUserState us,
		const char *accountname, const char *protocol, otrl_chat_token_t the_chat_token)
{
	OtrlChatContext *ctx;

	fprintf(stderr, "libotr-mpOTR: chat_context_find_or_add: start\n");

	fprintf(stderr, "libotr-mpOTR: chat_context_find_or_add: accountname: %s, protocol: %s\n", accountname, protocol);
	ctx = chat_context_find(us, accountname, protocol, the_chat_token);

	if(!ctx) {
		fprintf(stderr, "libotr-mpOTR: chat_context_find_or_add: before chat_context_create\n");
		ctx = chat_context_create(us, accountname, protocol, the_chat_token);
		if(ctx) {
			fprintf(stderr, "libotr-mpOTR: chat_context_find_or_add: before chat_context_add\n");
			if (!chat_context_add(us, ctx)) {
				chat_context_destroy((PayloadPtr)ctx);
				ctx = NULL;
			}
		}
	}


	fprintf(stderr, "libotr-mpOTR: chat_context_find_or_add: end\n");
	return ctx;
}

struct OtrlListOpsStruct chat_context_listOps = {
		chat_context_compare,
		chat_context_toString,
		chat_context_destroy
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
