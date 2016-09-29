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

#include "chat_types.h"

typedef enum {
	CHAT_DSKESTATE_NONE,
	CHAT_DSKESTATE_AWAITING_KEYS,
	CHAT_DSKESTATE_FINISHED
} ChatDSKEState;

int chat_dske_init(ChatContextPtr ctx, ChatMessage **msgToSend);

void chat_dske_info_free(ChatDSKEInfoPtr dske_info);

ChatDSKEState chat_dske_info_get_state(ChatDSKEInfoPtr dske_info);

int chat_dske_is_my_message(const ChatMessage *msg);

int chat_dske_handle_message(ChatContextPtr ctx, ChatMessage *msg,
		OtrlListPtr fnprnt_list, ChatMessage **msgToSend);
