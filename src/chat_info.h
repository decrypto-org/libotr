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

#ifndef CHAT_INFO_H
#define CHAT_INFO_H

#include "chat_types.h"

typedef enum {
	OTRL_CHAT_PRIVACY_LEVEL_NONE,
	OTRL_CHAT_PRIVACY_LEVEL_UNVERIFIED,
	OTRL_CHAT_PRIVACY_LEVEL_PRIVATE,
	OTRL_CHAT_PRIVACY_LEVEL_FINISHED,
	OTRL_CHAT_PRIVACY_LEVEL_UNKNOWN
} OtrlChatPrivacyLevel;

typedef struct OtrlChatInfoStruct * OtrlChatInfo;

OtrlChatInfo chat_info_new(const ChatContext ctx);
OtrlChatInfo chat_info_new_with_level(const ChatContext ctx);
void chat_info_free(OtrlChatInfo info);
char * otrl_chat_info_get_accountname(OtrlChatInfo info);
char * otrl_chat_info_get_protocol(OtrlChatInfo info);
otrl_chat_token_t otrl_chat_info_get_chat_token(OtrlChatInfo info);
OtrlChatPrivacyLevel otrl_chat_info_get_privacy_level(OtrlChatInfo info);

#endif /* CHAT_INFO_H */
