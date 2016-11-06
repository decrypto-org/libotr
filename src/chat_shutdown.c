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
#include "chat_message.h"
#include "chat_sign.h"
#include "chat_participant.h"

void chat_shutdown_info_destroy(OtrlShutdownInfo *shutdown_info)
{
	free(shutdown_info->has_send_end);
}

int chat_shutdown_init(OtrlChatContext *ctx)
{
    //OtrlListNode *cur;
    //OtrlChatParticipant *participant;
    //int error = 0;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_init: start\n");

    ctx->shutdown_info.has_send_end = calloc(otrl_list_length(ctx->participants_list),
                                             sizeof(*ctx->shutdown_info.has_send_end));
    if(!ctx->shutdown_info.has_send_end){
        return 1;
    }

    ctx->shutdown_info.remaining = otrl_list_length(ctx->participants_list) - 1;
    ctx->shutdown_info.state = OTRL_CHAT_SHUTDOWNSTATE_AWAITING_ENDS;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_init: end\n");

    return 0;
}

int chat_shutdown_send_end(OtrlChatContext *ctx, OtrlChatMessage **msgToSend)
{
    OtrlChatParticipant *me;
    unsigned int my_pos;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_end: start\n");

    me = chat_participant_find(ctx, ctx->accountname, &my_pos);
    if(!me) {
        return 1;
    }

    if(ctx->shutdown_info.has_send_end[my_pos]) {
        return 0;
    }

    *msgToSend = chat_message_shutdown_end_create(ctx);
    if(!*msgToSend) {
    	return 1;
    }

    //me->shutdown->state = SHUTDOWN_FINISHED;
    //ctx->shutdown_info.remaining -= 1;
    ctx->shutdown_info.has_send_end[my_pos] = 1; // True
    fprintf(stderr, "libotr-mpOTR: chat_shutdown_send_end: end\n");
    return 0;
}

int chat_shutdown_handle_end_message(OtrlChatContext *ctx, OtrlChatMessage *msg,
                                 OtrlChatMessage **msgToSend)
{
    OtrlChatParticipant *sender;
    unsigned int their_pos;
    int error = 0;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_end: start\n");

    sender = chat_participant_find(ctx, msg->senderName, &their_pos);
    if(!sender) {
        return 1;
    }

    if(ctx->shutdown_info.state != OTRL_CHAT_SHUTDOWNSTATE_AWAITING_ENDS) {
        return 1;
    }

    if(ctx->shutdown_info.has_send_end[their_pos]) {
        return 0;
    }

    error = chat_shutdown_send_end(ctx, msgToSend);
    if(error) {
        return 1;
    }
    ctx->shutdown_info.has_send_end[their_pos] = 1; // True
    ctx->shutdown_info.remaining -= 1;
    if(ctx->shutdown_info.remaining == 0) {
        ctx->shutdown_info.state = OTRL_CHAT_SHUTDOWNSTATE_FINISHED;
    }

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_handle_end: end\n");
    return 0;
}

int chat_shutdown_release_secrets(OtrlChatContext *ctx, OtrlChatMessage **msgToSend)
{
    unsigned char *key_bytes;
    size_t keylen;

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_release_secrets: start\n");

    chat_sign_serialize_privkey(ctx->signing_key, &key_bytes, &keylen);
	*msgToSend = chat_message_shutdown_keyrelease_create(ctx, key_bytes, keylen);
	if(!*msgToSend) {
		return 1;
	}

    fprintf(stderr, "libotr-mpOTR: chat_shutdown_release_secrets: end\n");

	return 0;
}

int chat_shutdown_is_my_message(const OtrlChatMessage *msg)
{
    OtrlChatMessageType msgType = msg->msgType;

    switch(msgType) {
        case OTRL_MSGTYPE_CHAT_SHUTDOWN_END:
            return 1;
        default:
            return 0;
    }
}

int chat_shutdown_handle_message(OtrlChatContext *ctx, OtrlChatMessage *msg,
                                 OtrlChatMessage **msgToSend)
{
	OtrlChatMessageType msgType = msg->msgType;
    switch(msgType) {
        case OTRL_MSGTYPE_CHAT_SHUTDOWN_END:
            return chat_shutdown_handle_end_message(ctx, msg, msgToSend);
        default:
            return 0;
    }
}
