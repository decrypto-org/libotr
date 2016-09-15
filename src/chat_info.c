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

#include <stdlib.h>

#include "chat_types.h"
#include "chat_participant.h"

int chat_info_privacy_level_calculate(const OtrlChatContext *ctx, OtrlChatInfoPrivacyLevel *privacy_level)
{
	ChatParticipant *me;
	OtrlChatInfoPrivacyLevel level;
	OtrlListNode *cur;
	unsigned int pos;
	unsigned char untrusted = 0;

	me = chat_participant_find(ctx, ctx->accountname, &pos);
	if(!me) { goto error; }

	switch(ctx->msg_state) {
		case OTRL_MSGSTATE_PLAINTEXT:
			level = LEVEL_NONE;
			break;

		case OTRL_MSGSTATE_ENCRYPTED:
			for(cur = ctx->participants_list->head; cur != NULL && !untrusted; cur = cur->next) {
				ChatParticipant *part = cur->payload;

				if(part != me) {
					OtrlChatFingerprint *finger = part->fingerprint;
					if(!finger) { goto error; }

					if (!finger->isTrusted) {
						untrusted = 1;
					}
				}
			}
			level = (untrusted) ? LEVEL_UNVERIFIED : LEVEL_PRIVATE;
			break;

		case OTRL_MSGSTATE_FINISHED:
			level = LEVEL_FINISHED;
			break;

		default:
			goto error;

	}

	*privacy_level = level;
	return 0;

error:
	fprintf(stderr, "libotr-mpOTR: chat_info_privacy_level_calculate: error\n");
	return 1;
}

OtrlChatInfo *chat_info_create(const OtrlChatContext *ctx)
{
	OtrlChatInfo *info;

	info = malloc(sizeof *info);
	if(!info) { goto error; }

	info->accountname = strdup(ctx->accountname);
	if(!info->accountname) { goto error_with_info; }

	info->protocol = strdup(ctx->protocol);
	if(!info->protocol) { goto error_with_accountname; }

	info->chat_token = ctx->the_chat_token;

	return info;

error_with_accountname:
	fprintf(stderr, "libotr-mpOTR: chat_info_create: error_with_accountname\n");
	free(info->accountname);
error_with_info:
	fprintf(stderr, "libotr-mpOTR: chat_info_create: error_with_info\n");
	free(info);
error:
	fprintf(stderr, "libotr-mpOTR: chat_info_create: error\n");
	return NULL;
}

OtrlChatInfo *chat_info_create_with_level(const OtrlChatContext *ctx)
{
	OtrlChatInfo *info;
	OtrlChatInfoPrivacyLevel level;
	int err;

	err = chat_info_privacy_level_calculate(ctx, &level);
	if(err) { goto error; }

	info = chat_info_create(ctx);
	if(!info) { goto error; }

	info->level = level;

	return info;

error:
	return NULL;
}

void chat_info_free(OtrlChatInfo *info)
{
	if(info) {
		free(info->accountname);
		free(info->protocol);
	}
	free(info);
}
