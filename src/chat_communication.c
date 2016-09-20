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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "chat_context.h"
#include "chat_enc.h"
#include "chat_message.h"
#include "chat_participant.h"
#include "chat_types.h"
#include "list.h"

int chat_communication_handle_data_message(ChatContext ctx, ChatMessage *msg,
										   ChatMessage **msgToSend, char** plaintext)
{
	ChatMessagePayloadData *payload = msg->payload;
    ChatParticipant sender;
    OtrlListNode node;
    unsigned int sender_pos;
	char *plain = NULL;
    char *plain_cpy = NULL;

    fprintf(stderr, "libotr-mpOTR: chat_communication_handle_data_message: start\n");

	switch(chat_context_get_msg_state(ctx)) {

		case OTRL_MSGSTATE_PLAINTEXT:
		case OTRL_MSGSTATE_FINISHED:
			goto error;
			break;

		case OTRL_MSGSTATE_ENCRYPTED:

			plain = chat_enc_decrypt(ctx, payload->ciphertext, payload->datalen, payload->ctr, msg->senderName);
			if (!plain) { goto error; }

            sender = chat_participant_find(chat_context_get_participants_list(ctx), msg->senderName, &sender_pos);
            if(!sender) {goto error_with_plain; }

            plain_cpy = strdup(plain);
            if(!plain_cpy) { goto error_with_plain; }

            node = otrl_list_insert(chat_participant_get_messages(sender), plain_cpy);
            if(!node) { goto error_with_copy; }

            otrl_list_dump(chat_participant_get_messages(sender));
			break;
	}

	*plaintext = plain;

	fprintf(stderr, "libotr-mpOTR: chat_communication_handle_data_message: end\n");

	return 0;

error_with_copy:
    free(plain_cpy);
error_with_plain:
    free(plain);
error:
	return 1;

}

int chat_communication_broadcast(ChatContext ctx, const char *message,
								 ChatMessage **msgToSend)
{
	unsigned char *ciphertext;
	OtrlListNode node;
	size_t datalen;
	ChatMessage *msg = NULL;
    ChatParticipant me;
    unsigned int pos;
    char *msg_cpy = NULL;

	fprintf(stderr, "libotr-mpOTR: chat_communication_broadcast: start\n");

    /* Find the user in the participants list */
    me = chat_participant_find(chat_context_get_participants_list(ctx), chat_context_get_accountname(ctx), &pos);
    if(!me) { goto error; }

    /* Copy the message to send */
    msg_cpy = strdup(message);
    if(!msg_cpy) { goto error; }

	ciphertext = chat_enc_encrypt(ctx, message);
	if(!ciphertext) { goto error_with_msg_cpy; }

	datalen = strlen(message);

	msg = chat_message_data_new(ctx, chat_context_get_enc_info(ctx)->ctr, datalen, ciphertext);
	if(!msg) { goto error_with_ciphertext; }

	//TODO Dimitris: maybe add a chat_participant_add_message function ,to avoid code duplication of allocation and error handling
    /* And insert the message he is sending, so that we can later execute
     * the shutdown phase */
    node = otrl_list_insert(chat_participant_get_messages(me), msg_cpy);
    if(!node) { goto error_with_msg; }

    otrl_list_dump(chat_participant_get_messages(me));

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

int chat_communication_handle_msg(ChatContext ctx, ChatMessage *msg,
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
