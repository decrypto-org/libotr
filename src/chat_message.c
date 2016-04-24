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
#include "chat_serial.h"


int otrl_chat_message_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *sender, otrl_chat_token_t chat_token, const char *message,
	char **newmessagep,	OtrlTLV **tlvsp)
{
	OtrlChatContext * ctx;
	OtrlChatMessageType msgtype;
	OtrlChatMessage *msg, *msgToSend = NULL;
	int ignore_message = 0; // flag to determine if the message should be ignored
	int err = 0;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: start\n");

	if( !accountname || !protocol || !sender || !message || !newmessagep)
		return 1;

	ctx = chat_context_find_or_add(us, accountname, protocol, chat_token);

	// TODO define return values
	if(!ctx)
		return 1;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: before chat_message_parse\n");
	msg = chat_message_parse(message);
	// TODO handle this case
	if(!msg)
		return 1;

	// TODO Dimitris: code refactoring, change checking against values using the appropriate handling functions
	// 				  using err and msgToSend
	msgtype = msg->msgType;
	if(msgtype == OTRL_MSGTYPE_CHAT_NOTOTR) {
		fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: case OTRL_MSGTYPE_NOTOTR\n");
		if (ctx->msg_state != OTRL_MSGSTATE_PLAINTEXT) {
			if(ops->handle_msg_event) {
				ops->handle_msg_event(/*opdata*/ NULL, OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED, NULL,  message, gcry_error(GPG_ERR_NO_ERROR));
				free(*newmessagep);
				*newmessagep = NULL;
				ignore_message = 1;
			}
		}

	// handle authentication messages
	} else if(chat_auth_is_auth_message(msg)) {
		fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: in chat_auth_is_auth_message\n");
		err = chat_auth_handle_message(ops, ctx, msg, &msgToSend);

	// handle data messages
	} else if(msgtype == OTRL_MSGTYPE_CHAT_DATA) {

		fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: case OTRL_MSGTYPE_CHAT_DATA\n");
		OtrlChatMessagePayloadData *payload = msg->payload;

		switch(ctx->msg_state) {
			char *plaintext;

			case OTRL_MSGSTATE_PLAINTEXT:
			case OTRL_MSGSTATE_FINISHED:
				/* TODO if plaintext or finished ignore the message. In the future handle this more gracefully */
				fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: case OTRL_MSGSTATE_PLAINTEXT OR OTRL_MSGSTATE_FINISHED\n");
				ignore_message = 1;
				break;

			case OTRL_MSGSTATE_ENCRYPTED:
				fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: case OTRL_MSGSTATE_ENCRYPTED\n");
				fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: sender: %s\n", sender);
				plaintext = chat_enc_decrypt(ctx, payload->ciphertext, payload->datalen, payload->ctr, sender);
				if (!plaintext) {
					/* ignore if there was an error. handle this more gracefully in the future */
					ignore_message = 1;
					break;
				}
				/* if we got here this means that we can display the message to the user */
				*newmessagep = plaintext;
				ignore_message = 0;
				break;
		}
	}

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: before if(err) \n");
	if(err) {
		ignore_message = 1;
		if(msgToSend)
			chat_message_free(msgToSend);
	}

	if(!err && msgToSend) {
		chat_message_send(ops, ctx, msgToSend);
		chat_message_free(msgToSend);
	}

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: before chat_message_free(msg) \n");
	chat_message_free(msg);

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_receiving: end\n");
	return ignore_message;
}

int otrl_chat_message_sending(OtrlUserState us,
	const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *message, otrl_chat_token_t chat_token, OtrlTLV *tlvs,
	char **messagep, OtrlFragmentPolicy fragPolicy)
{
	OtrlChatContext * ctx;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: start\n");

	if( !accountname || !protocol || !message) { goto error; }

	ctx = chat_context_find_or_add(us, accountname, protocol, chat_token);

	// TODO define better return values
	if(!ctx) { goto error; }

	switch(ctx->msg_state) {
		unsigned char *ciphertext;
		OtrlChatMessage *msg;
		size_t datalen;

		case OTRL_MSGSTATE_PLAINTEXT:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_PLAINTEXT\n");
			break;
		case OTRL_MSGSTATE_ENCRYPTED:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_ENCRYPTED\n");
			ciphertext = chat_enc_encrypt(ctx, message);
			if(!ciphertext)
				return 1;
			// TODO maybe get length from chat_enc_encrypt so that we can support other modes of aes
			datalen = strlen(message);
			msg = chat_message_data_create(ctx, ctx->enc_info.ctr, datalen, ciphertext);
			if(!msg) { goto error; }

			*messagep = chat_message_serialize(msg);
			chat_message_free(msg);

			break;
		case OTRL_MSGSTATE_FINISHED:
			fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: case OTRL_MSGSTATE_FINISHED\n");
			break;
	}

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_sending: end\n");

	return 0;

error:
	return 1;
}

int otrl_chat_message_send_query(OtrlUserState us,
		const OtrlMessageAppOps *ops,
		const char *accountname, const char *protocol,
		otrl_chat_token_t chat_token, OtrlFragmentPolicy fragPolicy)
{
	OtrlChatMessage *msg;
	OtrlChatContext *ctx;
	int err;

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_send_query: start\n");

	ctx = chat_context_find_or_add(us, accountname, protocol, chat_token);
	if(!ctx) { goto error; }

	err = chat_auth_init(ops, ctx, &msg);
	if(err) { goto error; }

	err = chat_message_send(ops, ctx, msg);
	if(err) { goto error_with_msg; }

	chat_message_free(msg);

	fprintf(stderr, "libotr-mpOTR: otrl_chat_message_send_query: end\n");

	return 0;

error_with_msg:
chat_message_free(msg);
error:
	return 1;
}

OtrlChatMessage * chat_message_parse(const char *message)
{
	OtrlChatMessage *msg;
	unsigned char *buf = NULL;
	size_t buflen;
	int res, err;

	msg = malloc(sizeof *msg);
	if(!msg) { goto error; }

	// TODO Dimtiris: maybe not return a struct in this case?
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
	if(chat_message_is_fragment(message)) { goto error_with_msg; }

	res = otrl_base64_otr_decode(message, &buf, &buflen);
	if(res != 0 || buflen < 11)	{ goto error_with_msg; }

	msg->protoVersion = chat_serial_string_to_int16(&buf[0]);
	msg->msgType = chat_message_message_type_parse(buf[2]);
	msg->senderInsTag = chat_serial_string_to_int(&buf[3]);
	msg->chatInsTag = chat_serial_string_to_int(&buf[7]);
	err = chat_message_payload_parse(msg, &buf[11], buflen-11);
	if(err) { goto error_with_msg; }

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

int chat_message_payload_parse(OtrlChatMessage *msg, const unsigned char *message, size_t length)
{
	if(!msg) { goto error; }

	switch(msg->msgType) {
		case OTRL_MSGTYPE_CHAT_UPFLOW:
			msg->payload_free = chat_message_payload_gka_upflow_free;
			msg->payload_serialize = chat_message_payload_gka_upflow_serialize;
			msg->payload = chat_message_payload_gka_upflow_parse(message, length);
			break;

		case OTRL_MSGTYPE_CHAT_DOWNFLOW:
			msg->payload_free = chat_message_payload_gka_downflow_free;
			msg->payload_serialize = chat_message_payload_gka_downflow_serialize;
			msg->payload = chat_message_payload_gka_downflow_parse(message, length);
			break;

		case OTRL_MSGTYPE_CHAT_DATA:
			msg->payload_free = chat_message_payload_data_free;
			msg->payload_serialize = chat_message_payload_data_serialize;
			msg->payload = chat_message_payload_data_parse(message, length);
			break;

		default:
			goto error;
	}

	return 0;

error:
	return 1;
}

char * chat_message_serialize(OtrlChatMessage *msg)
{
	char *message;
	unsigned char *buf;
	size_t buflen;

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: start\n");

	if(!msg || !msg->payload_serialize) { goto error; }

	unsigned char *payload_serialized = msg->payload_serialize(msg->payload, &buflen);
	if(!payload_serialized) { goto error; }

	buflen += 11;
	buf = malloc(buflen * sizeof *buf);
	if(!buf) { goto error_with_payload_serialized; }

	chat_serial_int16_to_string(msg->protoVersion, &buf[0]);
	buf[2] = chat_message_message_type_serialize(msg->msgType);
	chat_serial_int_to_string((int)msg->senderInsTag, &buf[3]);
	chat_serial_int_to_string((int)msg->chatInsTag, &buf[7]);
	memcpy(&buf[11], payload_serialized, buflen-11);

	//fprintf(stderr, "libotr-mpOTR: chat_message_serialize: serialized message:\n");
	//for(unsigned int i = 0; i<buflen;i++) fprintf(stderr,"%02X",buf[i]); fprintf(stderr,"\n");

	message = otrl_base64_otr_encode(buf, buflen);
	if(!message) { goto error_with_buf; }

	free(buf);
	free(payload_serialized);

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: end\n");

	return message;

error_with_buf:
	free(buf);
error_with_payload_serialized:
	free(payload_serialized);
error:
	return NULL;
}

MessagePayloadPtr chat_message_payload_data_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadData *payload;

	// 8 bytes for ctr, 4 for datalen
	if(length < 12) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	for(int i=0; i<8; i++) {
		payload->ctr[i] = message[i];
	}

	payload->datalen = chat_serial_string_to_int(&message[8]);

	if(length != 12 + payload->datalen) { goto error_with_payload; }

	payload->ciphertext = malloc(payload->datalen * sizeof *(payload->ciphertext));
	if(!(payload->ciphertext)) { goto error_with_payload; }

	memcpy(payload->ciphertext, &message[12], payload->datalen);

	return (MessagePayloadPtr)payload;

error_with_payload:
	free(payload);
error:
	return NULL;
}

void chat_message_payload_data_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadData *myPayload;

	myPayload = payload;

	if(myPayload) {
		if(myPayload->ciphertext) {
			free(myPayload->ciphertext);
		}
		free(myPayload);
	}
}

unsigned char * chat_message_payload_data_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	unsigned char *buf;
	OtrlChatMessagePayloadData *myPayload;

	myPayload = payload;

	// 8 bytes for ctr, 4 for datalen + datalen for data
	*payload_size = 12 + myPayload->datalen;
	buf = malloc(*payload_size * sizeof *buf);
	if(!buf) { goto error; }

	for(int i=0; i<8; i++) {
		buf[i] = myPayload->ctr[i];
	}

	chat_serial_int_to_string((int)myPayload->datalen, &buf[8]);
	memcpy(&buf[12], myPayload->ciphertext, myPayload->datalen);

	return buf;

error:
	return NULL;
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
		if(msg->payload_free && msg->payload) {
			msg->payload_free(msg->payload);
		}
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

int chat_message_is_fragment(const char * message)
{
	if(strstr(message, "?OTR|") == message)
		return 1;
	else
		return 0;
}

OtrlChatMessage * chat_message_create(OtrlChatContext *ctx, OtrlChatMessageType msgType)
{
	OtrlChatMessage *msg;

	msg = malloc(sizeof *msg);
	if(!msg) { goto error; }

	msg->protoVersion = ctx->protocol_version;
	msg->msgType = msgType;
	msg->senderInsTag = ctx->our_instance;
	msg->chatInsTag = OTRL_INSTAG_CHAT;
	msg->payload = NULL;
	msg->payload_free = NULL;
	msg->payload_serialize = NULL;

	return msg;

error:
	return NULL;
}

MessagePayloadPtr chat_message_payload_gka_upflow_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadGkaUpflow *payload;

	unsigned int pos = 0;
	int keysLength, i, keySize;
	gcry_mpi_t *key;

	// TODO check length

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_gka_upflow_parse: start\n");

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	payload->recipient = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	memcpy(payload->partlistHash, &message[pos], CHAT_PARTICIPANTS_HASH_LENGTH);
	pos += CHAT_PARTICIPANTS_HASH_LENGTH;
	keysLength = chat_serial_string_to_int(&message[pos]);
	pos += 4;

	payload->interKeys = otrl_list_init(&interKeyOps, sizeof(gcry_mpi_t));
	if(!payload->interKeys) { goto error_with_payload; }

	for(i=0; i<keysLength; i++) {
		keySize = chat_serial_string_to_int(&message[pos]);
		pos += 4;
		key = malloc(sizeof *key);
		if(!key) { goto error_with_payload_interKeys; }
		chat_serial_string_to_mpi(&message[pos], key, keySize);
		pos += keySize;
		otrl_list_append(payload->interKeys, key);
	}

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_gka_upflow_parse: end\n");

	return (MessagePayloadPtr)payload;

error_with_payload_interKeys:
	otrl_list_destroy(payload->interKeys);
error_with_payload:
	free(payload);
error:
	return NULL;
}

unsigned char * chat_message_payload_gka_upflow_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadGkaUpflow *myPayload;
	unsigned char *ret, **keys;
	unsigned int i;
	int err;
	size_t *keySizes;
	gcry_mpi_t *k;
	OtrlListNode *cur;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_gka_upflow_serialize: start\n");

	myPayload = payload;

	keys = malloc(myPayload->interKeys->size * sizeof *keys);
	if(!keys) { goto error; }

	keySizes = malloc(myPayload->interKeys->size * sizeof *keySizes);
	if(!keySizes) { goto error_with_keys; }

	*payload_size = 0;

	for(i = 0, cur = myPayload->interKeys->head; cur != NULL; i++, cur = cur->next) {
		k = cur->payload;
		err = chat_serial_mpi_to_string(*k, &keys[i], &keySizes[i]);
		if(err) {
			for(unsigned int j = 0; j < i; j++) { free(keys[i]); }
			goto error_with_keySizes;
		}
		*payload_size += keySizes[i] + 4;
	}

	// 4 recipient, CHAT_PARTICIPANTS_HASH_LENGTH partlistHash, 4 interkeys size header
	*payload_size += 8 + CHAT_PARTICIPANTS_HASH_LENGTH;

	ret = malloc(*payload_size * sizeof *ret);
	if(!ret) { goto error_with_filled_keys; }

	unsigned int pos = 0;

	chat_serial_int_to_string(myPayload->recipient, &ret[pos]);
	pos += 4;
	memcpy(&ret[pos], myPayload->partlistHash, CHAT_PARTICIPANTS_HASH_LENGTH);
	pos += CHAT_PARTICIPANTS_HASH_LENGTH;

	chat_serial_int_to_string(myPayload->interKeys->size, &ret[pos]);
	pos += 4;

	for(i=0; i<myPayload->interKeys->size; i++) {
		chat_serial_int_to_string(keySizes[i], &ret[pos]);
		pos += 4;
		memcpy(&ret[pos], keys[i], keySizes[i]);
		pos += keySizes[i];
	}

	for(i=0; i<myPayload->interKeys->size; i++) { free(keys[i]); }
	free(keySizes);
	free(keys);

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_gka_upflow_serialize: end\n");

	return ret;

error_with_filled_keys:
	for(i=0; i<myPayload->interKeys->size; i++) { free(keys[i]); }
error_with_keySizes:
	free(keySizes);
error_with_keys:
	free(keys);
error:
	return NULL;
}

void chat_message_payload_gka_upflow_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadGkaUpflow *myPayload = payload;

	otrl_list_destroy(myPayload->interKeys);
	free(myPayload);
}


MessagePayloadPtr chat_message_payload_gka_downflow_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadGkaDownflow *payload;

	unsigned int pos = 0;
	int keysLength, i, keySize;
	gcry_mpi_t *key;

	// TODO check length

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	memcpy(payload->partlistHash, &message[pos], CHAT_PARTICIPANTS_HASH_LENGTH);
	pos += CHAT_PARTICIPANTS_HASH_LENGTH;

	keysLength = chat_serial_string_to_int(&message[pos]);
	pos += 4;

	payload->interKeys = otrl_list_init(&interKeyOps, sizeof(gcry_mpi_t));
	if(!payload->interKeys) { goto error_with_payload; }

	for(i=0; i<keysLength; i++) {
		keySize = chat_serial_string_to_int(&message[pos]);
		pos += 4;
		key = malloc(sizeof *key);
		if(!key) { goto error_with_payload_interKeys; }
		chat_serial_string_to_mpi(&message[pos], key, keySize);
		pos += keySize;
		otrl_list_append(payload->interKeys, key);
	}

	return (MessagePayloadPtr)payload;

error_with_payload_interKeys:
	otrl_list_destroy(payload->interKeys);
error_with_payload:
	free(payload);
error:
	return NULL;
}

unsigned char * chat_message_payload_gka_downflow_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadGkaDownflow *myPayload;
	unsigned char *ret, **keys;
	unsigned int i;
	int err;
	size_t *keySizes;
	gcry_mpi_t *k;
	OtrlListNode *cur;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_gka_downflow_serialize: start\n");

	myPayload = payload;

	keys = malloc(myPayload->interKeys->size * sizeof *keys);
	if(!keys) { goto error; }

	keySizes = malloc(myPayload->interKeys->size * sizeof *keySizes);
	if(!keySizes) { goto error_with_keys; }

	*payload_size = 0;
	for(i = 0, cur = myPayload->interKeys->head; cur != NULL; i++, cur = cur->next) {
		k = cur->payload;
		err = chat_serial_mpi_to_string(*k, &keys[i], &keySizes[i]);
		if(err) {
			for(unsigned int j = 0; j < i; j++) { free(keys[i]); }
			goto error_with_keySizes;
		}
		*payload_size += keySizes[i] + 4;
	}

	// CHAT_PARTICIPANTS_HASH_LENGTH partlistHash, 4 interkeys size header
	*payload_size += 4 + CHAT_PARTICIPANTS_HASH_LENGTH;

	ret = malloc(*payload_size * sizeof *ret);
	if(!ret) { goto error_with_filled_keys; }

	unsigned int pos = 0;

	memcpy(&ret[pos], myPayload->partlistHash, CHAT_PARTICIPANTS_HASH_LENGTH);
	pos += CHAT_PARTICIPANTS_HASH_LENGTH;

	chat_serial_int_to_string(myPayload->interKeys->size, &ret[pos]);
	pos += 4;

	for(i=0; i<myPayload->interKeys->size; i++) {
		chat_serial_int_to_string(keySizes[i], &ret[pos]);
		pos += 4;
		memcpy(&ret[pos], keys[i], keySizes[i]);
		pos += keySizes[i];
	}

	for(i=0; i<myPayload->interKeys->size; i++) { free(keys[i]); }
	free(keySizes);
	free(keys);

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_gka_downflow_serialize: end\n");

	return ret;

error_with_filled_keys:
	for(i=0; i<myPayload->interKeys->size; i++) { free(keys[i]); }
error_with_keySizes:
	free(keySizes);
error_with_keys:
	free(keys);
error:
	return NULL;
}

void chat_message_payload_gka_downflow_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadGkaDownflow *myPayload = payload;

	otrl_list_destroy(myPayload->interKeys);
	free(myPayload);
}

OtrlChatMessage * chat_message_gka_upflow_create(OtrlChatContext *ctx, const unsigned char *partlistHash, OtrlList *interKeys, unsigned int recipient)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadGkaUpflow *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_UPFLOW);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->interKeys = interKeys;
	memcpy(payload->partlistHash, partlistHash, sizeof(payload->partlistHash));
	payload->recipient = recipient;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_gka_upflow_free;
	msg->payload_serialize = chat_message_payload_gka_upflow_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

OtrlChatMessage * chat_message_gka_downflow_create(OtrlChatContext *ctx, const unsigned char *partlistHash, OtrlList *interKeys)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadGkaDownflow *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_DOWNFLOW);
	if(!msg) {goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->interKeys = interKeys;
	memcpy(payload->partlistHash, partlistHash, sizeof(payload->partlistHash));

	msg->payload = payload;
	msg->payload_free = chat_message_payload_gka_downflow_free;
	msg->payload_serialize = chat_message_payload_gka_downflow_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

OtrlChatMessage * chat_message_data_create(OtrlChatContext *ctx, unsigned char *ctr, size_t datalen, unsigned char *ciphertext)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadData *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_DATA);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	memcpy(payload->ctr, ctr, 8);
	payload->datalen = datalen;
	payload->ciphertext = ciphertext;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_data_free;
	msg->payload_serialize = chat_message_payload_data_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

int chat_message_send(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, OtrlChatMessage *msg)
{
	char *message, *token;
	int chat_flag = 1;

	fprintf(stderr, "libotr-mpOTR: chat_message_send: start\n");

	message = chat_message_serialize(msg);
	if(!message){ goto err; }

	// TODO Dimtiris: this is a work-around to pass the token as a recipient string. We should change that ASAP
	// 				  maybe define another callback with this prototype:
	//				  inject_chat_message(const char * accountname, const char *protocol, otrl_chat_token_t token, const char *message)
	token = malloc(sizeof(int));
	if(!token) { goto err_with_message;	}

	memcpy(token, (char*)ctx->the_chat_token, sizeof(int));
	ops->inject_message(&chat_flag, ctx->accountname, ctx->protocol, token, message);

	free(token);
	free(message);

	fprintf(stderr, "libotr-mpOTR: chat_message_send: end\n");

	return 0;

err_with_message:
	free(message);
err:
	return 1;
}

