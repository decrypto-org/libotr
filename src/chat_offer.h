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

#include "message.h"
#include "chat_types.h"

#ifndef CHAT_OFFER_H_
#define CHAT_OFFER_H_

int chat_offer_handle_message(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, const OtrlChatMessage *msg, OtrlChatMessage **msgToSend);

int chat_offer_init(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, OtrlChatMessage **msgToSend);

int chat_offer_is_my_message(const OtrlChatMessage *msg);

#endif /* CHAT_OFFER_H_ */
