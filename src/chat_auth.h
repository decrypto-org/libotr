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

#ifndef CHAT_AUTH_H_
#define CHAT_AUTH_H_

//#include "chat_enc.h"
//#include "chat_context.h"
//#include "chat_message.h"
#include "chat_types.h"
//typedef enum {
//	OTRL_CHAT_AUTHSTATE_NONE,
//	OTRL_CHAT_AUTHSTATE_AWAITING_RES
//} OtrlAuthGKAState;
//
//typedef struct {
//	OtrlAuthGKAState state;  /* the gka state */
//
//	unsigned char key[32];
//
//	OtrlChatMessage *auth_msg; /* the next message to be send for GKA */
//} OtrlAuthGKAInfo;

/* Handle a chat query message msg using the ctx context. Prepares the Query response
 * and stores it in msgToSend */
gcry_error_t chat_auth_handle_query(OtrlChatContext *ctx, const OtrlChatMessage *msg,
		OtrlChatMessage **msgToSend);

/* Handles a chat query response message */
gcry_error_t chat_auth_handle_query_response(OtrlChatContext *ctx, const OtrlChatMessage *msg);
#endif /* CHAT_AUTH_H_ */
