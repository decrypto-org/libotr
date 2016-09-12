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

#ifndef CHAT_PENDING_H_
#define CHAT_PENDING_H_

typedef struct ChatPending* ChatPendingPtr;

size_t chat_pending_size();
ChatPendingPtr chat_pending_create(const char *sender, const unsigned char *msg, size_t msglen);
void chat_pending_free(ChatPendingPtr pending);
char *chat_pending_get_sender(ChatPendingPtr pending);
unsigned char *chat_pending_get_msg(ChatPendingPtr pending);
size_t chat_pending_get_msglen(ChatPendingPtr pending);

struct OtrlListOpsStruct chat_pending_listOps;

#endif /* CHAT_PENDING_H_ */
