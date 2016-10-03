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

#ifndef CHAT_ATTEST_H_
#define CHAT_ATTEST_H_

void chat_attest_info_free(ChatAttestInfo *info);

int chat_attest_init(OtrlChatContext *ctx, ChatMessage **msgToSend);

int chat_attest_handle_message(OtrlChatContext *ctx, const ChatMessage *msg, ChatMessage **msgToSend);

int chat_attest_is_my_message(ChatMessage *msg);

#endif /* CHAT_ATTEST_H_ */
