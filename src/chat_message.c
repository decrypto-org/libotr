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

#include <string.h>

/* libgcrypt headers */
#include <gcrypt.h>

/* libotr headers */
#include "privkey.h"
#include "userstate.h"
#include "proto.h"
#include "auth.h"
#include "message.h"
#include "sm.h"
#include "instag.h"
#include "list.h"
#include "chat_token.h"
#include "chat_context.h"
#include "chat_message.h"
#include "chat_auth.h"
#include "chat_enc.h"
#include "b64.h"
 

int otrl_chat_message_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *sender, otrl_chat_token_t chat_token, const char *message,
	char **newmessagep,	OtrlTLV **tlvsp)
{
	OtrlChatContext * ctx;
	OtrlMessageType msgtype;
	OtrlChatMessage *msg, *msgToSend = NULL;
	int ignore_message = 0; // flag to determine if the message should be ignored
	int res;

	fprintf(stderr, "\n\nlibotr-mpOTR: otrl_chat_message_receiving: start\n");

	if( !accountname || !protocol || !sender || !message || !newmessagep)
		return 1;
	/*
	 * TODO
	 * - Find or create context
	 * - Check if the message is plaintext
	 *   - if yes:
	 *   	if msgstate == PLAINTEXT
	 *   		display message
	 *   	else
	 *   		inform user and display message
	 *   - if no:
	 *   	parse message type
	 *   	case query:
	 *   		sync ephemeral symmetric encryption key
	 *   		reply????
	 *   		msgstate <- ENCRYPTED
	 *   	case error:
	 *   		inform user
	 *   	case data:
	 *   		if: msgstate == ENCRYPTED
	 *  	 		Find encryption key for that context
	 *  	 		Verify message
	 *   			decrypt in *newmessagep
	 *   		else:
	 *   			Inform and send error message
	 */

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: before chat_context_find_or_add\n");
	ctx = chat_context_find_or_add(us, accountname, protocol, chat_token);

	// TODO define return values
	if(!ctx)
		return 1;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: before chat_message_parse\n");
	msg = chat_message_parse(message);
	// TODO handle this case
	if(!msg)
		return 1;

	msgtype = msg->msgType;
	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: before switch (msgtype)\n");
	switch (msgtype) {
		gcry_error_t err;
		case OTRL_MSGTYPE_NOTOTR:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: case OTRL_MSGTYPE_NOTOTR\n");
			if (ctx->msg_state != OTRL_MSGSTATE_PLAINTEXT) {
				if(ops->handle_msg_event) {
					ops->handle_msg_event(/*opdata*/ NULL,
							OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED,
							NULL,  message, gcry_error(GPG_ERR_NO_ERROR));
					free(*newmessagep);
					*newmessagep = NULL;
					ignore_message = 1;
				}
			}
			break;

		/* TODO change name to avoid confusion */
		case OTRL_MSGTYPE_CHAT_QUERY:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: case OTRL_MSGTYPE_CHAT_QUERY\n");
			err = chat_auth_handle_query(ctx, msg, &msgToSend);
			if(msgToSend) {
				res = chat_message_send(ops, ctx, msgToSend);
				chat_message_free(msgToSend);
				if(!res)
					return 1;
			}
			ignore_message = 1; //this message should bot be displayed to the user
			break;

		case OTRL_MSGTYPE_CHAT_QUERY_ACK:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: case OTRL_MSGTYPE_CHAT_QUERY_ACK\n");
			// TODO check that this is correct
			err = chat_auth_handle_query_response(ctx, msg);
			break;

		case OTRL_MSGTYPE_CHAT_DATA:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: case OTRL_MSGTYPE_CHAT_DATA\n");
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: before switch(ctx->msg_state)\n");
			switch(ctx->msg_state) {
				/* TODO if plaintext or finished ignore the message. In the future handle this
				 * more gracefully */
				char *plaintext;

				case OTRL_MSGSTATE_PLAINTEXT:
				case OTRL_MSGSTATE_FINISHED:
					fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: case OTRL_MSGSTATE_PLAINTEXT OR OTRL_MSGSTATE_FINISHED\n");
					ignore_message = 1;
					break;

				case OTRL_MSGSTATE_ENCRYPTED:
					fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: case OTRL_MSGSTATE_ENCRYPTED\n");
					plaintext = chat_enc_decrypt(ctx, ((OtrlChatMessagePayloadData *)msg->payload)->ciphertext,
							((OtrlChatMessagePayloadData *)msg->payload)->datalen, ((OtrlChatMessagePayloadData *)msg->payload)->ctr);
					if (!plaintext) {
						/* ignore if there was an error. handle this more gracefully in
						 * the future */
						ignore_message = 1;
						break;
					}
					/* if we got here this means that we can display the message to the user */
					*newmessagep = plaintext;
					ignore_message = 0;
					break;
			}

	}

	chat_message_free(msg);

	fprintf(stderr, "\n\nlibotr-mpOTR: otrl_chat_message_receiving: end\n\n\n");
	return ignore_message;
}

int otrl_chat_message_sending(OtrlUserState us,
	const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *message, otrl_chat_token_t chat_token, OtrlTLV *tlvs,
	char **messagep, OtrlFragmentPolicy fragPolicy)
{
	OtrlChatContext * ctx;

	fprintf(stderr, "\n\nlibotr-mpOTR: otrl_chat_message_sending: start\n");
	fprintf(stderr, "    accountname: %s, protocol: %s, chat_token: %d, message: %s\n", accountname, protocol, *((int *)chat_token), message);

	fprintf(stderr, "dumping the context list:\n");
	otrl_list_dump(us->chat_context_list);

	if( !accountname || !protocol || !message)
		return 1;
	/*
	 * TODO
	 * 1. Find or create context
	 * 2. Find encryption key for that context
	 * 3. Encrypt message
	 * 4. Put message in *messagep
	 */

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: before chat_context_find_or_add\n");
	ctx = chat_context_find_or_add(us, accountname, protocol, chat_token);

	// TODO define better return values
	if(!ctx)
		return 1;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: after chat_context_find_or_add\n");

	switch(ctx->msg_state) {
		unsigned char *ciphertext;
		OtrlChatMessage *msg;
		size_t datalen;

		case OTRL_MSGSTATE_PLAINTEXT:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_PLAINTEXT\n");
			// TODO Dimitris: remove this....
			if(strstr(message, "?OTR?") == message) {
				fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: before chat_message_query_create\n");
				chat_enc_initialize_cipher(&(ctx->enc_info));
				//msg = chat_message_query_create(ctx->protocol_version, ctx->our_instance, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
				msg = chat_message_query_create(ctx->protocol_version, ctx->our_instance, ctx->enc_info.key);
				if(!msg) {
					chat_message_free(msg);
					return 1;
				}
				fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: before chat_message_serialize\n");
				*messagep = chat_message_serialize(msg);
				fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: before chat_message_free\n");
				chat_message_free(msg);
			}

			break;
		case OTRL_MSGSTATE_ENCRYPTED:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_ENCRYPTED\n");
			ciphertext = chat_enc_encrypt(ctx, message);
			if(!ciphertext)
				return 1;
			// TODO maybe get length from chat_enc_encrypt so that we can support other modes of aes
			datalen = strlen(message);
			msg = chat_message_data_create(ctx->protocol_version, ctx->our_instance, ctx->enc_info.ctr, datalen, ciphertext);
			if(!msg) {
				chat_message_free(msg);
				return 1;
			}
			*messagep = chat_message_serialize(msg);
			chat_message_free(msg);

			break;
		case OTRL_MSGSTATE_FINISHED:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_FINISHED\n");
			break;
	}

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: eend\n\n\n");

	return 0;
}

OtrlChatMessage * chat_message_parse(const char *message)
{
	OtrlChatMessage *msg;
	unsigned char *buf = NULL;
	size_t buflen;
	int res;

	fprintf(stderr, "libotr-mpOTR: chat_message_parse: start\n");
	msg = (OtrlChatMessage *)malloc(sizeof(OtrlChatMessage));
	if(!msg)
		return NULL;

	// TODO Dimtiris: maybe not return a struct in this case?
	fprintf(stderr, "libotr-mpOTR: chat_message_parse: before if\n");
	if(!chat_message_is_otr(message)) {
		msg->protoVersion = 0;
		msg->msgType = OTRL_MSGTYPE_NOTOTR;
		msg->senderInsTag = 0;
		msg->chatInsTag = 0;
		msg->payload = NULL;
		msg->payload_free = NULL;
		msg->payload_serialize = NULL;
		return msg;
	}

	// TODO: handle this case
	if(chat_message_is_fragment(message))
		return NULL;

	fprintf(stderr, "libotr-mpOTR: chat_message_parse: before otrl_base64_otr_decode\n");
	res = otrl_base64_otr_decode(message, &buf, &buflen);
	if(res != 0)
		return NULL;
	if(buflen < 11)							// TODO Dimitris: better handling maybe with defined values
		return NULL;

	// TODO Dimitris: make some better functions to convert
	fprintf(stderr, "libotr-mpOTR: chat_message_parse: before converts\n");
	msg->protoVersion = buf[0] << 8 | buf[1];
	msg->msgType = chat_message_message_type_parse(buf[2]);
	msg->senderInsTag = (buf[3] << 24) | (buf[4] << 16) | (buf[5] << 8) | buf[6];
	msg->chatInsTag = (buf[7] << 24) | (buf[8] << 16) | (buf[9] << 8) | buf[10];

	fprintf(stderr, "libotr-mpOTR: chat_message_parse: before chat_message_payload_parse\n");
	if(!chat_message_payload_parse(msg, &buf[11], buflen-11)) {
		chat_message_free(msg);
		return NULL;
	}

	return msg;
}

MessagePayloadPtr chat_message_payload_parse(OtrlChatMessage *msg, const unsigned char *message, size_t length)
{
	fprintf(stderr, "libotr-mpOTR: chat_message_payload_parse: start\n");
	if(!msg)
		return NULL;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_parse: before switch\n");
	switch(msg->msgType) {
		case OTRL_MSGTYPE_CHAT_QUERY:
			fprintf(stderr, "libotr-mpOTR: chat_message_payload_parse: case OTRL_MSGTYPE_CHAT_QUERY\n");
			msg->payload_free = chat_message_payload_query_free;
			msg->payload_serialize = chat_message_payload_query_serialize;
			msg->payload = chat_message_payload_query_parse(message, length);
			break;

		case OTRL_MSGTYPE_CHAT_QUERY_ACK:
			fprintf(stderr, "libotr-mpOTR: chat_message_payload_parse: case OTRL_MSGTYPE_CHAT_QUERY_ACK\n");
			msg->payload_free = chat_message_payload_query_ack_free;
			msg->payload_serialize = chat_message_payload_query_ack_serialize;
			msg->payload = chat_message_payload_query_ack_parse(message, length);
			break;

		case OTRL_MSGTYPE_CHAT_DATA:
			fprintf(stderr, "libotr-mpOTR: chat_message_payload_parse: case OTRL_MSGTYPE_CHAT_DATA\n");
			msg->payload_free = chat_message_payload_data_free;
			msg->payload_serialize = chat_message_payload_data_serialize;
			msg->payload = chat_message_payload_data_parse(message, length);
			break;

		default:
			fprintf(stderr, "libotr-mpOTR: chat_message_payload_parse: default\n");
			return NULL;
	}

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_parse: before return\n");
	return msg->payload;
}

char * chat_message_serialize(OtrlChatMessage *msg)
{
	char *message = NULL;
	unsigned char *buf;
	size_t buflen;

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: start\n");

	if(!msg || !msg->payload_serialize)
		return NULL;

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before chat_message_payload_size\n");
	buflen = chat_message_payload_size(msg);
	if(!buflen)
		return NULL;

	buflen += 11;
	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before malloc, buflen: %ld\n", buflen);
	buf = (unsigned char *)malloc(buflen*sizeof(unsigned char));
	if(!buf)
		return NULL;

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before msg->payload_serialize\n");
	unsigned char *payload_serialized = msg->payload_serialize(msg->payload);
	if(!payload_serialized) {
		free(buf);
		return NULL;
	}

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before protoVersion\n");
	buf[0] = (msg->protoVersion >> 8) & 0xff;
	buf[1] = msg->protoVersion & 0xff;
	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before chat_message_message_type_serialize\n");
	buf[2] = chat_message_message_type_serialize(msg->msgType);
	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before senderInsTag\n");
	buf[3] = (msg->senderInsTag >> 24) & 0xff;
	buf[4] = (msg->senderInsTag >> 16) & 0xff;
	buf[5] = (msg->senderInsTag >> 8) & 0xff;
	buf[6] = msg->senderInsTag & 0xff;
	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before chatInsTag\n");
	buf[7] = (msg->chatInsTag >> 24) & 0xff;
	buf[8] = (msg->chatInsTag >> 16) & 0xff;
	buf[9] = (msg->chatInsTag >> 8) & 0xff;
	buf[10] = msg->chatInsTag & 0xff;
	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before memcpy, buflen-11: %d\n", buflen-11);
	memcpy(&buf[11], payload_serialized, buflen-11);

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before otrl_base64_otr_encode\n");
	message = otrl_base64_otr_encode(buf, buflen);

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before free\n");
	free(buf);

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: end\n");
	return message;
}

MessagePayloadPtr chat_message_payload_query_parse(const unsigned char * message, size_t length)
{
	OtrlChatMessagePayloadQuery *payload;
	size_t key_size = 32; 						// TODO Dimitris: define values????

	payload = (OtrlChatMessagePayloadQuery *)malloc(sizeof(OtrlChatMessagePayloadQuery));
	if(!payload)
		return NULL;

	if(length == key_size) {
		memcpy(payload->key, message, key_size);
	}

	return (MessagePayloadPtr)payload;
}

void chat_message_payload_query_free(MessagePayloadPtr payload)
{
	free(payload);
}

unsigned char * chat_message_payload_query_serialize(MessagePayloadPtr payload)
{
	return ((OtrlChatMessagePayloadQuery *)payload)->key;
}

MessagePayloadPtr chat_message_payload_query_ack_parse(const unsigned char * message, size_t length)
{
	OtrlChatMessagePayloadQueryAck *payload;
	size_t magicnum_size = 4; 						// TODO Dimitris: define values????

	payload = (OtrlChatMessagePayloadQueryAck *)malloc(sizeof(OtrlChatMessagePayloadQueryAck));
	if(!payload)
		return NULL;

	if(length == magicnum_size) {
		memcpy(payload->magicnum, message, magicnum_size);
	}

	return (MessagePayloadPtr)payload;
}

void chat_message_payload_query_ack_free(MessagePayloadPtr payload)
{
	free(payload);
}

unsigned char * chat_message_payload_query_ack_serialize(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadQueryAck *myPayload;
	myPayload = (OtrlChatMessagePayloadQueryAck *)payload;
	return myPayload->magicnum;
}

MessagePayloadPtr chat_message_payload_data_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadData *payload;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_data_parse: start\n");

	// 8 bytes for ctr, 4 for datalen
	if(length < 12)
		return NULL;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_data_parse: before malloc\n");
	payload = (OtrlChatMessagePayloadData *)malloc(sizeof(OtrlChatMessagePayloadData));
	if(!payload)
		return NULL;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_data_parse: before ctr\n");
	for(int i=0; i<8; i++) {
		payload->ctr[i] = message[i];
	}

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_data_parse: before datalen\n");
	payload->datalen = (message[8] << 24) | (message[9] << 16) | (message[10] << 8) | message[11];

	// 8 bytes for ctr, 4 for datalen, datalen for data
	if(length != 12 + payload->datalen) {
		free(payload);
		return NULL;
	}

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_data_parse: before malloc\n");
	payload->ciphertext = malloc(payload->datalen*sizeof(char));
	if(!payload) {
		free(payload);
		return NULL;
	}

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_data_parse: before memcpy\n");
	memcpy(payload->ciphertext, &message[12], payload->datalen);

	return (MessagePayloadPtr)payload;
}

void chat_message_payload_data_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadData *myPayload;
	myPayload = (OtrlChatMessagePayloadData *)payload;

	if(myPayload) {
		if(myPayload->ciphertext)
			free(myPayload->ciphertext);
		free(myPayload);
	}
}

unsigned char * chat_message_payload_data_serialize(MessagePayloadPtr payload)
{
	unsigned char *buf;
	OtrlChatMessagePayloadData *myPayload;
	myPayload = (OtrlChatMessagePayloadData *)payload;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_data_serialize: start\n");

	// 8 bytes for ctr, 4 for datalen + datalen for data
	buf =malloc((8+4+myPayload->datalen) * sizeof *buf);
	if(!buf)
		return NULL;

	for(int i=0; i<8; i++)
		buf[i] = myPayload->ctr[i];

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_data_serialize: before datalen, datalen: %ld\n", myPayload->datalen);
	// TODO use a function or define to make the big endian encoding
	buf[8] = (myPayload->datalen >> 24) & 0xff;
	buf[9] = (myPayload->datalen >> 16) & 0xff;
	buf[10] = (myPayload->datalen >> 8) & 0xff;
	buf[11] = myPayload->datalen & 0xff;
	memcpy(&buf[12], myPayload->ciphertext, myPayload->datalen);

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_data_serialize: end\n");
	return buf;
}

size_t chat_message_payload_size(OtrlChatMessage *msg)
{
	if(!msg || !msg->payload)
		return -1;

	switch(msg->msgType) {
		case OTRL_MSGTYPE_CHAT_QUERY:
			return 32;
			break;
		case OTRL_MSGTYPE_CHAT_QUERY_ACK:
			return 4;
			break;
		case OTRL_MSGTYPE_CHAT_DATA:
			// TODO 8 ctr, 4 datalen, len ciphertext
			return 12 + ((OtrlChatMessagePayloadData *)msg->payload)->datalen;
			break;
		default:
			return -1;

	}
}

OtrlMessageType chat_message_message_type_parse(unsigned char c)
{
	return (OtrlMessageType)c;	// TODO Dimitris: do the actual mapping
}

unsigned char chat_message_message_type_serialize(OtrlMessageType msgType)
{
	return ((unsigned char)msgType);
}

void chat_message_free(OtrlChatMessage * msg)
{
	if(msg) {
		if(msg->payload_free && msg->payload)
			msg->payload_free(msg->payload);
		free(msg);
	}
}

int chat_message_is_otr(const char * message)
{
	if(strstr(message, "?OTR") == message)
		return 1;
	else
		return 0;
}

int chat_message_is_fragment(const char * message) {
	if(strstr(message, "?OTR|") == message)
		return 1;
	else
		return 0;
}

OtrlChatMessage * chat_message_create(unsigned int proto_version, OtrlMessageType msgType ,otrl_instag_t our_instag)
{
	OtrlChatMessage *msg;

	msg = (OtrlChatMessage *)malloc(sizeof(OtrlChatMessage));
	if(!msg)
		return NULL;

	msg->protoVersion = proto_version;
	msg->msgType = msgType;
	msg->senderInsTag = our_instag;
	msg->chatInsTag = OTRL_INSTAG_CHAT;
	msg->payload = NULL;
	msg->payload_free = NULL;
	msg->payload_serialize = NULL;

	return msg;
}

OtrlChatMessage * chat_message_query_create(int16_t proto_version,
		otrl_instag_t our_instag, const unsigned char *key)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadQuery *payload;
	fprintf(stderr, "libotr-mpOTR: chat_message_query_create: start\n");

	fprintf(stderr, "libotr-mpOTR: chat_message_query_create: before chat_message_create\n");
	msg = chat_message_create(proto_version, OTRL_MSGTYPE_CHAT_QUERY, our_instag);
	if(!msg)
		return NULL;

	fprintf(stderr, "libotr-mpOTR: chat_message_query_create: before payload malloc\n");
	payload = (OtrlChatMessagePayloadQuery *)malloc(sizeof(OtrlChatMessagePayloadQuery));
	if(!payload) {
		chat_message_free(msg);
		return NULL;
	}

	fprintf(stderr, "libotr-mpOTR: chat_message_query_create: before memcpy\n");
	memcpy(payload->key, key, 32);

	fprintf(stderr, "libotr-mpOTR: chat_message_query_create: before other assignments\n");
	msg->payload = payload;
	msg->payload_free = chat_message_payload_query_free;
	msg->payload_serialize = chat_message_payload_query_serialize;


	return msg;
}

OtrlChatMessage * chat_message_query_ack_create(int16_t protoVersion,
		otrl_instag_t ourInstag)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadQueryAck *payload;

	msg = chat_message_create(protoVersion, OTRL_MSGTYPE_CHAT_QUERY_ACK, ourInstag);
	if(!msg)
		return NULL;

	payload = (OtrlChatMessagePayloadQueryAck *)malloc(sizeof(OtrlChatMessagePayloadQueryAck));
	if(!payload) {
		chat_message_free(msg);
		return NULL;
	}

	// TODO this is to change. For now magicnum = 1234 :-D
	for(int i=0; i<4; i++)
		payload->magicnum[i] = i+1;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_query_ack_free;
	msg->payload_serialize = chat_message_payload_query_ack_serialize;

	return msg;
}

OtrlChatMessage * chat_message_data_create(int16_t protoVersion,
		otrl_instag_t ourInstag, unsigned char *ctr, size_t datalen, unsigned char *ciphertext)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadData *payload;

	msg = chat_message_create(protoVersion, OTRL_MSGTYPE_CHAT_DATA, ourInstag);
	if(!msg)
		return NULL;

	payload = (OtrlChatMessagePayloadData *)malloc(sizeof(OtrlChatMessagePayloadData));
	if(!payload) {
		chat_message_free(msg);
		return NULL;
	}

	memcpy(payload->ctr, ctr, 8);
	payload->datalen = datalen;
	payload->ciphertext = ciphertext;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_data_free;
	msg->payload_serialize = chat_message_payload_data_serialize;

	return msg;
}

int chat_message_send(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, OtrlChatMessage *msg)
{
	char *message, *token;
	int chat_flag = 1;

	fprintf(stderr, "libotr-mpOTR: chat_message_send: start\n");

	message = chat_message_serialize(msg);
	if(!message)
		return -1;

	fprintf(stderr, "libotr-mpOTR: chat_message_send: serialized message: %s\n", message);

	// TODO Dimtiris: this is a work-around to pass the token as a recipient string. We should change that ASAP
	// 				  maybe define another callback with this prototype:
	//				  inject_chat_message(const char * accountname, const char *protocol, otrl_chat_token_t token, const char *message)
	token = malloc(sizeof(int));
	if(!token) return -1;
	fprintf(stderr, "libotr-mpOTR: chat_message_send: before memcpy\n");
	memcpy(token, (char*)ctx->the_chat_token, sizeof(int));

	fprintf(stderr, "libotr-mpOTR: chat_message_send: before inject_message\n");
	ops->inject_message(&chat_flag, ctx->accountname, ctx->protocol, token, message);

	fprintf(stderr, "libotr-mpOTR: chat_message_send: before free\n");
	free(token);
	free(message);


	fprintf(stderr, "libotr-mpOTR: chat_message_send: end\n");

	return 1;
}

