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
#include "chat_types.h"

OtrlChatContext* chat_context_find(OtrlUserState us, const OtrlMessageAppOps *ops,
		const char *accountname, const char *protocol, otrl_chat_token_t the_chat_token);

int chat_context_add(OtrlUserState us, OtrlChatContext* ctx);

int chat_context_reset(OtrlChatContext *ctx);

OtrlChatContext* chat_context_find_or_add(OtrlUserState us, const OtrlMessageAppOps *ops,
		const char *accountname, const char *protocol, otrl_chat_token_t the_chat_token);

struct OtrlListOpsStruct chat_context_listOps;

#endif /* CHAT_CONTEXT_H_ */
