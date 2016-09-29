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

#include "chat_info.h"

#include <stdlib.h>

#include "chat_context.h"
#include "chat_types.h"
#include "chat_participant.h"
#include "list.h"

struct OtrlChatInfo {
	char *accountname;
	char *protocol;
	otrl_chat_token_t chat_token;
	OtrlChatPrivacyLevel privacy_level;
};

int chat_info_privacy_level_calculate(const ChatContextPtr ctx, OtrlChatPrivacyLevel *privacy_level)
{
	OtrlChatPrivacyLevel level;
	OtrlListIteratorPtr iter;
	OtrlListNodePtr cur;
	ChatParticipantPtr me, part;
	OtrlChatFingerprintPtr fnprnt;
	unsigned int pos;
	unsigned char untrusted = 0;

	me = chat_participant_find(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &pos);
	if(!me) { goto error; }

	switch(chat_context_get_msg_state(ctx)) {
		case OTRL_MSGSTATE_PLAINTEXT:
			level = OTRL_CHAT_PRIVACY_LEVEL_NONE;
			break;

		case OTRL_MSGSTATE_ENCRYPTED:
			iter = otrl_list_iterator_new(chat_context_get_participants_list(ctx));
			if(!iter) { goto error; }
			while(otrl_list_iterator_has_next(iter)) {
				cur = otrl_list_iterator_next(iter);
				part = otrl_list_node_get_payload(cur);
				if(part != me) {
					fnprnt = chat_participant_get_fingerprint(part);
					if(!fnprnt) { goto error_with_iter; }

					if (0 == otrl_chat_fingerprint_is_trusted(fnprnt)) {
						untrusted = 1;
					}
				}
			}
			otrl_list_iterator_free(iter);
			level = (untrusted) ? OTRL_CHAT_PRIVACY_LEVEL_UNVERIFIED : OTRL_CHAT_PRIVACY_LEVEL_PRIVATE;
			break;

		case OTRL_MSGSTATE_FINISHED:
			level = OTRL_CHAT_PRIVACY_LEVEL_FINISHED;
			break;

		default:
			goto error;

	}

	*privacy_level = level;
	return 0;

error_with_iter:
	otrl_list_iterator_free(iter);
error:
	return 1;
}

OtrlChatInfoPtr chat_info_new(const ChatContextPtr ctx)
{
	OtrlChatInfoPtr info;

	info = malloc(sizeof *info);
	if(!info) { goto error; }

	info->accountname = strdup(chat_context_get_accountname(ctx));
	if(!info->accountname) { goto error_with_info; }

	info->protocol = strdup(chat_context_get_protocol(ctx));
	if(!info->protocol) { goto error_with_accountname; }

	info->chat_token = chat_context_get_chat_token(ctx);
	info->privacy_level = OTRL_CHAT_PRIVACY_LEVEL_UNKNOWN;

	return info;

error_with_accountname:
	free(info->accountname);
error_with_info:
	free(info);
error:
	return NULL;
}

OtrlChatInfoPtr chat_info_new_with_level(const ChatContextPtr ctx)
{
	OtrlChatInfoPtr info;
	OtrlChatPrivacyLevel level;
	int err;

	err = chat_info_privacy_level_calculate(ctx, &level);
	if(err) { goto error; }

	info = chat_info_new(ctx);
	if(!info) { goto error; }

	info->privacy_level = level;

	return info;

error:
	return NULL;
}

void chat_info_free(OtrlChatInfoPtr info)
{
	if(info) {
		free(info->accountname);
		free(info->protocol);
	}
	free(info);
}

char * otrl_chat_info_get_accountname(OtrlChatInfoPtr info)
{
	return info->accountname;
}

char * otrl_chat_info_get_protocol(OtrlChatInfoPtr info)
{
	return info->protocol;
}

otrl_chat_token_t otrl_chat_info_get_chat_token(OtrlChatInfoPtr info)
{
	return info->chat_token;
}

OtrlChatPrivacyLevel otrl_chat_info_get_privacy_level(OtrlChatInfoPtr info)
{
	return info->privacy_level;
}


