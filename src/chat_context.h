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

#include "chat_types.h"
#include "message.h"
#include "userstate.h"

size_t chat_context_size();
void chat_context_reset(ChatContext ctx);

unsigned int chat_context_get_protocol_version(ChatContext ctx);
char * chat_context_get_accountname(const ChatContext ctx);
char * chat_context_get_protocol(const ChatContext ctx);
otrl_chat_token_t chat_context_get_chat_token(const ChatContext ctx);
otrl_instag_t chat_context_get_our_instag(ChatContext ctx);
unsigned int chat_context_get_id(ChatContext ctx);
void chat_context_set_id(ChatContext ctx, unsigned int id);

OtrlList chat_context_get_participants_list(const ChatContext ctx);
OtrlList chat_context_get_pending_list(const ChatContext ctx);

unsigned char * chat_context_get_sid(const ChatContext ctx);

ChatOfferInfo chat_context_get_offer_info(const ChatContext ctx);
void chat_context_set_offer_info(ChatContext ctx, ChatOfferInfo offer_info);
ChatDSKEInfo chat_context_get_dske_info(const ChatContext ctx);
void chat_context_set_dske_info(ChatContext ctx, ChatDSKEInfo dske_info);
ChatGKAInfo chat_context_get_gka_info(const ChatContext ctx);
void chat_context_set_gka_info(ChatContext ctx, ChatGKAInfo gka_info);
ChatAttestInfo chat_context_get_attest_info(const ChatContext ctx);
void chat_context_set_attest_info(ChatContext ctx, ChatAttestInfo attest_info);
ChatEncInfo * chat_context_get_enc_info(const ChatContext ctx);
void chat_context_set_enc_info(ChatContext ctx, ChatEncInfo *enc_info);
ChatShutdownInfo chat_context_get_shutdown_info(const ChatContext ctx);
void chat_context_set_shutdown_info(ChatContext ctx, ChatShutdownInfo shutdown_info);

OtrlMessageState chat_context_get_msg_state(const ChatContext ctx);
void chat_context_set_msg_state(ChatContext ctx, OtrlMessageState state);
ChatSignState chat_context_get_sign_state(const ChatContext ctx);
void chat_context_set_sign_state(ChatContext ctx, ChatSignState state);

SignKey * chat_context_get_signing_key(const ChatContext ctx);
void chat_context_set_signing_key(ChatContext ctx, SignKey *signing_key);
ChatIdKey * chat_context_get_identity_key(ChatContext ctx);
void chat_context_set_identity_key(ChatContext ctx, ChatIdKey *identity_key);

ChatContext chat_context_find(OtrlList context_list, const char *accountname,
		const char *protocol, otrl_chat_token_t the_chat_token, otrl_instag_t instag);

ChatContext chat_context_find_or_add(OtrlList context_list, const char *accountname,
		const char *protocol, otrl_chat_token_t the_chat_token, otrl_instag_t instag);

struct OtrlListOpsStruct chat_context_listOps;

#endif /* CHAT_CONTEXT_H_ */
