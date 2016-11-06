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
void chat_context_reset(ChatContextPtr ctx);

unsigned int chat_context_get_mpotr_version(ChatContextPtr ctx);
char * chat_context_get_accountname(const ChatContextPtr ctx);
char * chat_context_get_protocol(const ChatContextPtr ctx);
otrl_chat_token_t chat_context_get_chat_token(const ChatContextPtr ctx);
otrl_instag_t chat_context_get_our_instag(ChatContextPtr ctx);
unsigned int chat_context_get_id(ChatContextPtr ctx);
void chat_context_set_id(ChatContextPtr ctx, unsigned int id);

OtrlListPtr chat_context_get_participants_list(const ChatContextPtr ctx);
OtrlListPtr chat_context_get_pending_list(const ChatContextPtr ctx);

unsigned char * chat_context_get_sid(const ChatContextPtr ctx);

ChatOfferInfoPtr chat_context_get_offer_info(const ChatContextPtr ctx);
void chat_context_set_offer_info(ChatContextPtr ctx, ChatOfferInfoPtr offer_info);
ChatDSKEInfoPtr chat_context_get_dske_info(const ChatContextPtr ctx);
void chat_context_set_dske_info(ChatContextPtr ctx, ChatDSKEInfoPtr dske_info);
ChatGKAInfoPtr chat_context_get_gka_info(const ChatContextPtr ctx);
void chat_context_set_gka_info(ChatContextPtr ctx, ChatGKAInfoPtr gka_info);
ChatAttestInfoPtr chat_context_get_attest_info(const ChatContextPtr ctx);
void chat_context_set_attest_info(ChatContextPtr ctx, ChatAttestInfoPtr attest_info);
ChatEncInfo * chat_context_get_enc_info(const ChatContextPtr ctx);
void chat_context_set_enc_info(ChatContextPtr ctx, ChatEncInfo *enc_info);
ChatShutdownInfoPtr chat_context_get_shutdown_info(const ChatContextPtr ctx);
void chat_context_set_shutdown_info(ChatContextPtr ctx, ChatShutdownInfoPtr shutdown_info);

OtrlMessageState chat_context_get_msg_state(const ChatContextPtr ctx);
void chat_context_set_msg_state(ChatContextPtr ctx, OtrlMessageState state);
ChatSignState chat_context_get_sign_state(const ChatContextPtr ctx);
void chat_context_set_sign_state(ChatContextPtr ctx, ChatSignState state);

SignKey * chat_context_get_signing_key(const ChatContextPtr ctx);
void chat_context_set_signing_key(ChatContextPtr ctx, SignKey *signing_key);
ChatIdKeyPtr chat_context_get_identity_key(ChatContextPtr ctx);
void chat_context_set_identity_key(ChatContextPtr ctx, ChatIdKeyPtr identity_key);

ChatContextPtr chat_context_find(OtrlListPtr context_list, const char *accountname,
		const char *protocol, otrl_chat_token_t the_chat_token, otrl_instag_t instag);

ChatContextPtr chat_context_find_or_add(OtrlListPtr context_list, const char *accountname,
		const char *protocol, otrl_chat_token_t the_chat_token, otrl_instag_t instag);

struct OtrlListOpsStruct chat_context_listOps;

#endif /* CHAT_CONTEXT_H_ */
