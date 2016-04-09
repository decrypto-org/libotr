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

#include "chat_message.h"
#include "chat_enc.h"
#include "instag.h"

/*
void chat_auth_create_query_message(OtrlAuthGKAInfo *gka_info, unsigned int proto_version,
									otrl_instag_t our_instag)
{
	OtrlChatMessage the_msg = malloc(sizeof(OtrlChatMessage));
	OtrlChatMessagePayloadQuery q_msg = malloc(sizeof(OtrlChatMessagePayloadQuery));

	the_msg->protoVersion = proto_version;
	the_msg->msgType = OTRL_MSGTYPE_CHAT_QUERY;
	the_msg->senderInsTag = our_instag;
	the_msg->chatInsTag = OTRL_INSTAG_CHAT;
	the_msg->payload = q_msg;
	the_msg->payload_free = NULL; // TODO add the cleanup  function

	memcpy(q_msg->key, gka_info.key, 32);

	free(gka_info->auth_msg);
	gka_info->auth_msg = the_msg;
}

*/
/* Creates a response for the query message */

/*void chat_auth_create_response_message(OtrlAuthGKAInfo *gka_info, unsigned int proto_version,
									   otrl_instag_t our_instag, )
{
	OtrlChatMessage *the_msg = malloc(sizeof(OtrlChatMessage));
	OtrlChatMessagePayloadQueryAck *ack_msg = malloc(sizeof(OtrlChatMessagePayloadQueryAck));

	the_msg->protoVersion = proto_version;
	the_msg->msgType = OTRL_MSGTYPE_CHAT_QUERY_ACK;
	the_msg->senderInsTag = our_instag;
	the_msg->chatInsTag = OTRL_INSTAG_CHAT;
	the_msg->payload = ack_msg;
	the_msg->payload_free = NULL; // TODO add the cleanup function

	for(int i=0; i<4; i++)
		ack_msg->magicnum[i] = i;

	free(gka_info->auth_msg);
	gka_info->auth_msg = the_msg;
}
*/
gcry_error_t chat_auth_handle_query(OtrlChatContext *ctx, const OtrlChatMessage *msg, OtrlChatMessage **msgToSend)
{
	//Parse message
	//OtrlChatMessageType *msg = chat_message_parse(message);
	gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

	//Parse the payload to get the query message struct
	//OtrlQueryMessageType *qmsg = chat_auth_parse_query_payload(msg->payload);
	OtrlChatMessagePayloadQuery *payload = msg->payload;
	//TODO Dimitris: should we check if payload is NULL????

	//set the key tin the ctx->gka_info
	if(!payload->key)
		return gcry_error(GPG_ERR_NO_DATA);
	//TODO please dimitris, check if this is correct
    //ctx->gka_info.key = payload->key;
    //TODO fix this hardcoded value
    memcpy(ctx->gka_info.key, payload->key, 32);
	//use the context to sync keys with the group
	err = chat_enc_sync_key(&ctx->enc_info, &ctx->gka_info);

	// TODO Dimitris: should we concern about type mismatch in protocol version???
	// TODO Dimtiris: maybe we should also change the way chat instag is defined
	*msgToSend = chat_message_query_ack_create(ctx->protocol_version, ctx->our_instance);
	if(!*msgToSend) {
		// TODO Dimtiris: mandragore please set a meaningful error type here
		err = gcry_error(GPG_ERR_NO_DATA);
	}

	ctx->gka_info.state = OTRL_CHAT_AUTHSTATE_NONE;
	ctx->msg_state = OTRL_MSGSTATE_ENCRYPTED;
	return err;
}

gcry_error_t chat_auth_handle_query_response(OtrlChatContext *ctx, const OtrlChatMessage *msg)
{
	gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

	//get the payload
	OtrlChatMessagePayloadQueryAck *payload = msg->payload;

	if(!payload->magicnum) {
	    fprintf(stderr, "libotr-mpOTR: chat_auth_handle_query_response: !magicnum\n");
	    return gcry_error(GPG_ERR_NO_DATA);
	}


	// check if the magicnum is 0x00 0x01 0x02 0x03
	// by xor'ing each magicnum byte with i.
	// xoring a value with itself always returns 0
	for(int i=0; i<4; i++)
		if(payload->magicnum[i] != i+1) {
		    fprintf(stderr, "libotr-mpOTR: chat_auth_handle_query_response: wrong magicnum %d %d\n",i, payload->magicnum[i]);
		    return gcry_error(GPG_ERR_INV_VALUE);
		}

	ctx->gka_info.state = OTRL_CHAT_AUTHSTATE_NONE;
	ctx->msg_state = OTRL_MSGSTATE_ENCRYPTED;

	return err;
}


