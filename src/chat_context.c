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

#include "chat_context.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chat_attest.h"
#include "chat_dske.h"
#include "chat_enc.h"
#include "chat_gka.h"
#include "chat_offer.h"
#include "chat_participant.h"
#include "chat_pending.h"
#include "chat_shutdown.h"
#include "chat_token.h"
#include "chat_types.h"
#include "context.h"
#include "instag.h"
#include "list.h"

struct ChatContextStruct {
		unsigned int protocol_version;     	/* The version of OTR in use */

		/* Context information that is meant for application use */
        char * accountname;                 /* The username is relative to this account... */
        char * protocol;                    /* ... and this protocol */
        otrl_chat_token_t the_chat_token;   /* The token of the chat */
        otrl_instag_t our_instag;         	/* Our instance tag for this computer*/

        unsigned int id;					/* Our id in this chat */

        unsigned char sid[CHAT_OFFER_SID_LENGTH];

        OtrlList participants_list;			/* The users in this chatroom */
        OtrlList pending_list; 			    /* The pending messages */

        ChatOfferInfo offer_info;
        ChatDSKEInfo dske_info;	    		/* Info needed for the DSKE */
        ChatGKAInfo gka_info;          		/* Info needed for the GKA */
        ChatAttestInfo attest_info;
        ChatEncInfo *enc_info;          	/* Info needed for encrypting messages */
        ChatShutdownInfo shutdown_info;

        OtrlMessageState msg_state;
        ChatSignState sign_state;

        SignKey *signing_key;		   		/* The signing key */
        ChatIdKey *identity_key;
};

size_t chat_context_size()
{
	return sizeof(struct ChatContextStruct);
}

ChatContext chat_context_new(const char *accountname, const char *protocol, otrl_chat_token_t the_chat_token, otrl_instag_t instag)
{
	ChatContext ctx;

	ctx = malloc(sizeof *ctx);
	if(!ctx) { goto error; }

	ctx->accountname = strdup(accountname);
	if(!ctx->accountname) { goto error_with_ctx; }

	ctx->protocol = strdup(protocol);
	if(!ctx->protocol) { goto error_with_accountname; }

	ctx->our_instag = instag;

	ctx->the_chat_token = the_chat_token;

	ctx->protocol_version = CHAT_PROTOCOL_VERSION;
	ctx->sign_state = CHAT_SIGNSTATE_NONE;
	ctx->msg_state = OTRL_MSGSTATE_PLAINTEXT;

	ctx->participants_list = otrl_list_new(&chat_participant_listOps, chat_participant_size());
	if(!ctx->participants_list) { goto error_with_protocol; }

	ctx->pending_list = otrl_list_new(&chat_pending_listOps, chat_pending_size());
	if(!ctx->pending_list) { goto error_with_participants_list; }

	ctx->offer_info = NULL;
	ctx->attest_info = NULL;
	ctx->dske_info = NULL;
    ctx->gka_info = NULL;
	ctx->enc_info = NULL;
	ctx->shutdown_info = NULL;
	ctx->signing_key = NULL;

	return ctx;

error_with_participants_list:
	otrl_list_free(ctx->participants_list);
error_with_protocol:
	free(ctx->protocol);
error_with_accountname:
	free(ctx->accountname);
error_with_ctx:
	free(ctx);
error:
	return NULL;
}

void chat_context_reset(ChatContext ctx)
{
	otrl_list_clear(ctx->participants_list);
	otrl_list_clear(ctx->pending_list);

	chat_offer_info_free(ctx->offer_info);
	ctx->offer_info = NULL;

	chat_attest_info_free(ctx->attest_info);
	ctx->attest_info = NULL;

	chat_dske_info_free(ctx->dske_info);
	ctx->dske_info = NULL;

	chat_gka_info_free(ctx->gka_info);
    ctx->gka_info = NULL;

	chat_enc_info_free(ctx->enc_info);
	ctx->enc_info = NULL;

	chat_shutdown_info_free(ctx->shutdown_info);
	ctx->shutdown_info = NULL;

	free(ctx->signing_key);
	ctx->signing_key = NULL;

	ctx->sign_state = CHAT_SIGNSTATE_NONE;
	ctx->msg_state = OTRL_MSGSTATE_PLAINTEXT;
}

void chat_context_free(ChatContext ctx)
{
	if(ctx) {
		free(ctx->accountname);
		free(ctx->protocol);
		otrl_list_free(ctx->participants_list);
		otrl_list_free(ctx->pending_list);
		chat_offer_info_free(ctx->offer_info);
		chat_dske_info_free(ctx->dske_info);
		chat_gka_info_free(ctx->gka_info);
		chat_attest_info_free(ctx->attest_info);
		chat_enc_info_free(ctx->enc_info);
		chat_shutdown_info_free(ctx->shutdown_info);
		free(ctx->signing_key);
	}
	free(ctx);
}

unsigned int chat_context_get_protocol_version(ChatContext ctx)
{
	return ctx->protocol_version;
}

char * chat_context_get_accountname(const ChatContext ctx)
{
	return ctx->accountname;
}

char * chat_context_get_protocol(const ChatContext ctx)
{
	return ctx->protocol;
}

otrl_chat_token_t chat_context_get_chat_token(const ChatContext ctx)
{
	return ctx->the_chat_token;
}

otrl_instag_t chat_context_get_our_instag(ChatContext ctx)
{
	return ctx->our_instag;
}

unsigned int chat_context_get_id(ChatContext ctx)
{
	return ctx->id;
}

void chat_context_set_id(ChatContext ctx, unsigned int id)
{
	ctx->id = id;
}

OtrlList chat_context_get_participants_list(const ChatContext ctx)
{
	return ctx->participants_list;
}

OtrlList chat_context_get_pending_list(const ChatContext ctx)
{
	return ctx->pending_list;
}

unsigned char * chat_context_get_sid(const ChatContext ctx)
{
	return ctx->sid;
}

ChatOfferInfo chat_context_get_offer_info(const ChatContext ctx)
{
	return ctx->offer_info;
}

void chat_context_set_offer_info(ChatContext ctx, ChatOfferInfo offer_info)
{
	ctx->offer_info = offer_info;
}

ChatDSKEInfo chat_context_get_dske_info(const ChatContext ctx)
{
	return ctx->dske_info;
}

void chat_context_set_dske_info(ChatContext ctx, ChatDSKEInfo dske_info)
{
	ctx->dske_info = dske_info;
}

ChatGKAInfo chat_context_get_gka_info(const ChatContext ctx)
{
	return ctx->gka_info;
}

void chat_context_set_gka_info(ChatContext ctx, ChatGKAInfo gka_info)
{
	ctx->gka_info = gka_info;
}

ChatAttestInfo chat_context_get_attest_info(const ChatContext ctx)
{
	return ctx->attest_info;
}

void chat_context_set_attest_info(ChatContext ctx, ChatAttestInfo attest_info)
{
	ctx->attest_info = attest_info;
}

ChatEncInfo * chat_context_get_enc_info(const ChatContext ctx)
{
	return ctx->enc_info;
}

void chat_context_set_enc_info(ChatContext ctx, ChatEncInfo *enc_info)
{
	ctx->enc_info = enc_info;
}

ChatShutdownInfo chat_context_get_shutdown_info(const ChatContext ctx)
{
	return ctx->shutdown_info;
}

void chat_context_set_shutdown_info(ChatContext ctx, ChatShutdownInfo shutdown_info)
{
	ctx->shutdown_info = shutdown_info;
}

OtrlMessageState chat_context_get_msg_state(const ChatContext ctx)
{
	return ctx->msg_state;
}

void chat_context_set_msg_state(ChatContext ctx, OtrlMessageState state)
{
	ctx->msg_state = state;
}

ChatSignState chat_context_get_sign_state(const ChatContext ctx)
{
	return ctx->sign_state;
}

void chat_context_set_sign_state(ChatContext ctx, ChatSignState state)
{
	ctx->sign_state = state;
}

SignKey * chat_context_get_signing_key(const ChatContext ctx)
{
	return ctx->signing_key;
}

void chat_context_set_signing_key(ChatContext ctx, SignKey *signing_key)
{
	ctx->signing_key = signing_key;
}

ChatIdKey * chat_context_get_identity_key(ChatContext ctx)
{
	return ctx->identity_key;
}

void chat_context_set_identity_key(ChatContext ctx, ChatIdKey *identity_key)
{
	ctx->identity_key = identity_key;
}

int chat_context_compare(ChatContext a, ChatContext b)
{
	int res = 0;

	res = strcmp(a->accountname, b->accountname);
	if(res == 0) {
		res = strcmp(a->protocol, b->protocol);
		if(res == 0) {
			res = chat_token_compare(a->the_chat_token, b->the_chat_token);
		}
	}

	return res;
}

void chat_context_print(ChatContext ctx)
{
	fprintf(stderr, "OtrlChatContext:\n");
	fprintf(stderr, "|-accountname   : %s\n", chat_context_get_accountname(ctx));
	fprintf(stderr, "|-protocol      : %s\n", chat_context_get_protocol(ctx));
	fprintf(stderr, "|-our_instag  : %d\n", chat_context_get_our_instag(ctx));
	// TODO change the way we typecast the_chat_token
	fprintf(stderr, "|-the_chat_token: %d\n", chat_context_get_chat_token(ctx));
}

int chat_context_add(OtrlList context_list, ChatContext ctx)
{
	OtrlListNode node;

	node = otrl_list_insert(context_list, (OtrlListPayload)ctx);
	if(!node) {goto error; }

	return 0;

error:
	return 1;
}

int chat_context_remove(OtrlList context_list, ChatContext ctx) {
	OtrlListNode node;

	node = otrl_list_find(context_list, (OtrlListPayload)ctx);
	if(!node) { goto error; }

	otrl_list_remove_and_free(context_list, node);

	return 0;

error:
	return 1;

}

ChatContext chat_context_find(OtrlList context_list, const char *accountname,
		const char *protocol, otrl_chat_token_t the_chat_token, otrl_instag_t instag)
{
	OtrlListNode node;
	ChatContext target, res;

	target = chat_context_new(accountname, protocol, the_chat_token, instag);
	if(!target) { goto error; }

	otrl_list_dump(context_list);

	node = otrl_list_find(context_list, (OtrlListPayload)target);
	if(!node) { goto error_with_target; }

	res = otrl_list_node_get_payload(node);

	chat_context_free(target);

	return res;

error_with_target:
	chat_context_free(target);
error:
	return NULL;
}

ChatContext chat_context_find_or_add(OtrlList context_list, const char *accountname,
		const char *protocol, otrl_chat_token_t the_chat_token, otrl_instag_t instag)
{
	ChatContext ctx;
	int err;

	ctx = chat_context_find(context_list, accountname, protocol, the_chat_token, instag);

	if(!ctx) {
		ctx = chat_context_new(accountname, protocol, the_chat_token, instag);
		if(!ctx) { goto error; }
		err = chat_context_add(context_list, ctx);
		if(err) { goto error_with_ctx; }
	}

	return ctx;

error_with_ctx:
	chat_context_free(ctx);
error:
	return NULL;
}

int chat_context_compareOp(OtrlListPayload a, OtrlListPayload b)
{
	ChatContext ctx1 = a;
	ChatContext ctx2 = b;

	return chat_context_compare(ctx1, ctx2);
}

void chat_context_printOp(OtrlListNode node)
{
	ChatContext ctx;

	ctx = otrl_list_node_get_payload(node);
	chat_context_print(ctx);
}

void chat_context_freeOp(OtrlListPayload a)
{
	ChatContext ctx;

	ctx = a;
	chat_context_free(ctx);
}

struct OtrlListOpsStruct chat_context_listOps = {
		chat_context_compareOp,
		chat_context_printOp,
		chat_context_freeOp
};
