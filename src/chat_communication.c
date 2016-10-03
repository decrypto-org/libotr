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

#include <stdio.h>
#include <string.h>

#include "chat_message.h"
#include "chat_enc.h"
#include "chat_participant.h"

int chat_communication_handle_data_message(OtrlChatContext *ctx, ChatMessage *msg,
										   ChatMessage **msgToSend, char** plaintext)
{
	ChatMessagePayloadData *payload = msg->payload;
    ChatParticipant *sender = NULL;
    OtrlListNode *node = NULL;
    unsigned int sender_pos;
	char *plain = NULL;
    char *plain_cpy = NULL;

	switch(ctx->msg_state) {

		case OTRL_MSGSTATE_PLAINTEXT:
		case OTRL_MSGSTATE_FINISHED:
			/* TODO if plaintext or finished ignore the message. In the future handle this more gracefully */
			goto error;
			break;

		case OTRL_MSGSTATE_ENCRYPTED:
			plain = chat_enc_decrypt(ctx, payload->ciphertext,
										 payload->datalen, payload->ctr,
                                         msg->senderName);

			/* TODO ignore if there was an error. handle this more gracefully in the future */
			if (!plain) { goto error; }

            sender = chat_participant_find(ctx, msg->senderName, &sender_pos);
            if(!sender) {goto error_with_plain; }

            plain_cpy = strdup(plain);
            if(!plain_cpy) { goto error_with_plain; }

            node = otrl_list_insert(sender->messages, plain_cpy);
            if(!node) { goto error_with_copy; }

            otrl_list_dump(sender->messages);
			break;
	}

	*plaintext = plain;

	return 0;

error_with_copy:
    free(plain_cpy);
error_with_plain:
    free(plain);
error:
	return 1;

}

int chat_communication_broadcast(OtrlChatContext *ctx, const char *message,
								 ChatMessage **msgToSend)
{
	unsigned char *ciphertext;
	OtrlListNode *node;
	size_t datalen;
	ChatMessage *msg = NULL;
    ChatParticipant *me = NULL;
    unsigned int pos;
    char *msg_cpy = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_communication_broadcast: start\n");

    /* Find the user in the participants list */
    me = chat_participant_find(ctx, ctx->accountname, &pos);
    if(!me) { goto error; }

    /* Copy the message to send */
    msg_cpy = strdup(message);
    if(!msg_cpy) { goto error; }

	ciphertext = chat_enc_encrypt(ctx, message);
	if(!ciphertext) { goto error_with_msg_cpy; }

	// TODO maybe get length from chat_enc_encrypt so that we can support other modes of aes
	datalen = strlen(message);

	msg = chat_message_data_create(ctx, ctx->enc_info.ctr, datalen, ciphertext);
	if(!msg) { goto error_with_ciphertext; }

    /* And insert the message he is sending, so that we can later execute
     * the shutdown phase */
    node = otrl_list_insert(me->messages, msg_cpy);
    if(!node) { goto error_with_msg; }

    otrl_list_dump(me->messages);

    fprintf(stderr, "libotr-mpOTR: chat_communication_broadcast: end\n");

	*msgToSend = msg;
	return 0;

error_with_msg:
	chat_message_free(msg);
error_with_ciphertext:
	free(ciphertext);
error_with_msg_cpy:
	free(msg_cpy);
error:
	return 1;
}

int chat_communication_is_my_message(ChatMessage *msg)
{
    ChatMessageType msg_type = msg->msgType;

    fprintf(stderr, "libotr-mpOTR: chat_communication_is_communication_message: start\n");

    switch(msg_type) {
        case CHAT_MSGTYPE_DATA:
            fprintf(stderr, "libotr-mpOTR: chat_communication_is_communication_message: it is\n");
            return 1;
        default:
    fprintf(stderr, "libotr-mpOTR: chat_communication_is_communication_message: it is not\n");
            return 0;
    }

}

int chat_communication_handle_msg(OtrlChatContext *ctx, ChatMessage *msg,
                                  ChatMessage **msgToSend, char **plaintext)
{
    ChatMessageType msg_type = msg->msgType;
    int err;
    char *plain;

    fprintf(stderr, "libotr-mpOTR: chat_communication_handle_message: start\n");

    switch(msg_type) {
        case CHAT_MSGTYPE_DATA:
            fprintf(stderr, "libotr-mpOTR: chat_communication_handle_message: data\n");
            err = chat_communication_handle_data_message(ctx, msg, msgToSend, &plain);
            if(err) { goto error; }
            break;
        default:
            goto error;
    }

    *plaintext = plain;
    return 0;

error:
	return 1;
}
