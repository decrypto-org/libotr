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

#include "chat_message.h"
#include "chat_enc.h"

int chat_communication_handle_data_message(OtrlChatContext *ctx, ChatMessage *msg,
										   ChatMessage **msgToSend, char** plaintext)
{
	ChatMessagePayloadData *payload = msg->payload;
	char *plain = NULL;

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
			break;
	}

	*plaintext = plain;
	return 0;

error:
	return 1;

}

int chat_communication_broadcast(OtrlChatContext *ctx, const char *message,
								 ChatMessage **msgToSend)
{
	unsigned char *ciphertext;
	size_t datalen;
	ChatMessage *msg = NULL;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_ENCRYPTED\n");

	ciphertext = chat_enc_encrypt(ctx, message);
	if(!ciphertext) { goto error; }

	// TODO maybe get length from chat_enc_encrypt so that we can support other modes of aes
	datalen = strlen(message);

	msg = chat_message_data_create(ctx, ctx->enc_info.ctr, datalen, ciphertext);
    //TODO when handling this error should the ciphertext be free'd?
	if(!msg) { goto error_with_ciphertext; }

	*msgToSend = msg;
	return 0;

error_with_ciphertext:
	free(ciphertext);
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
