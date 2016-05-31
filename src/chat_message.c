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
#include <stdlib.h>

/* libgcrypt headers */
#include <gcrypt.h>

/* libotr headers */
#include "b64.h"
#include "list.h"
#include "message.h"
#include "chat_serial.h"
#include "chat_auth.h"

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

OtrlMessageType chat_message_message_type_parse(unsigned char c)
{
	return (OtrlMessageType)c;	// TODO Dimitris: do the actual mapping
}


unsigned char * chat_message_payload_offer_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	unsigned int pos = 0;
	unsigned char *ret;
	OtrlChatMessagePayloadOffer *myPayload = payload;

	ret = malloc((4 + CHAT_OFFER_SID_CONTRIBUTION_LENGTH)* sizeof *ret);
	if(!ret) { goto error; }

	*payload_size = 4 + CHAT_OFFER_SID_CONTRIBUTION_LENGTH;

	chat_serial_int_to_string(myPayload->position, &ret[pos]);
	pos += 4;
	memcpy(&ret[pos], myPayload->sid_contribution, CHAT_OFFER_SID_CONTRIBUTION_LENGTH);
	pos += CHAT_OFFER_SID_CONTRIBUTION_LENGTH;

	return ret;

error:
	return NULL;
}

MessagePayloadPtr chat_message_payload_offer_parse(const unsigned char *message, size_t length)
{
	unsigned int pos = 0;
	OtrlChatMessagePayloadOffer *payload;

	if(length != 4 + CHAT_OFFER_SID_CONTRIBUTION_LENGTH) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	payload->position = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	memcpy(payload->sid_contribution, &message[pos], CHAT_OFFER_SID_CONTRIBUTION_LENGTH);
	pos += CHAT_OFFER_SID_CONTRIBUTION_LENGTH;

	return (MessagePayloadPtr)payload;

error:
	return NULL;
}

void chat_message_payload_offer_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadOffer *myPayload = payload;
	free(myPayload);
}

unsigned char * chat_message_payload_dake_handshake_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadDAKEHandshake *myPayload = payload;
	unsigned char *buf;
	unsigned int pos = 0;
	int err;
	unsigned char *ephem_pub, *long_pub;
	size_t ephem_size, long_size;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_handshake_serialize: start\n");

	err = chat_serial_mpi_to_string(myPayload->handshake_data.ephem_pub, &ephem_pub, &ephem_size);
	if(err) { goto error; }
	err = chat_serial_mpi_to_string(myPayload->handshake_data.long_pub, &long_pub, &long_size);
	if(err) { goto error_with_ehpem_pub; }

	//4 for ephem_size, ephem_size for ephem_pub, 4 for long_size, long_size for long_pub
	*payload_size = 8 + ephem_size + long_size;

	buf = malloc(*payload_size * sizeof *buf);
	if(!buf) { goto error_with_long_pub; }

	chat_serial_int_to_string(ephem_size, &buf[pos]);
	pos += 4;
	memcpy(&buf[pos], ephem_pub, ephem_size);
	pos += ephem_size;
	chat_serial_int_to_string(long_size, &buf[pos]);
	pos += 4;
	memcpy(&buf[pos], long_pub, long_size);
	pos += long_size;

	free(long_pub);
	free(ephem_pub);

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_handshake_serialize: end\n");

	return buf;

error_with_long_pub:
	free(long_pub);
error_with_ehpem_pub:
	free(ephem_pub);
error:
	return NULL;
}

MessagePayloadPtr chat_message_payload_dake_handshake_parse(const unsigned char *message, size_t length)
{
	unsigned int pos = 0;
	OtrlChatMessagePayloadDAKEHandshake *payload;
	size_t ephem_size, long_size;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_handshake_parse: start\n");

	if(length < 8) { goto error; }

	payload = malloc(sizeof *payload);

	ephem_size = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	if(length < 8 + ephem_size) { goto error_with_payload; }
	chat_serial_string_to_mpi(&message[pos], &payload->handshake_data.ephem_pub, ephem_size);
	pos += ephem_size;
	long_size = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	if(length != 8 + ephem_size+ long_size) { goto error_with_payload; }
	chat_serial_string_to_mpi(&message[pos], &payload->handshake_data.long_pub, long_size);
	pos += long_size;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_handshake_parse: end\n");

	return payload;

error_with_payload:
	free(payload);
error:
	return NULL;
}

void chat_message_payload_dake_handshake_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadDAKEHandshake *myPayload = payload;
	free(myPayload);
}

unsigned char * chat_message_payload_dake_confirm_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadDAKEConfirm *myPayload = payload;
	unsigned char *buf;
	unsigned int pos = 0;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_confirm_serialize: start\n");

	*payload_size = 4 + TDH_MAC_LENGTH;

	buf = malloc(*payload_size * sizeof *buf);
	if(!buf) { goto error; }

	chat_serial_int_to_string(myPayload->recipient, &buf[pos]);
	pos += 4;
	memcpy(&buf[pos], myPayload->data.mac, TDH_MAC_LENGTH);
	pos += TDH_MAC_LENGTH;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_confirm_serialize: end\n");

	return buf;

error:
	return NULL;
}

MessagePayloadPtr chat_message_payload_dake_confirm_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadDAKEConfirm *payload;
	unsigned int pos = 0;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_confirm_parse: start\n");

	if(length != 4 + TDH_MAC_LENGTH) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	payload->recipient = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	memcpy(payload->data.mac, &message[pos], TDH_MAC_LENGTH);
	pos += TDH_MAC_LENGTH;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_confirm_parse: end\n");

	return payload;

error:
	return NULL;
}

void chat_message_payload_dake_confirm_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadDAKEConfirm *myPayload = payload;
	free(myPayload);
}

unsigned char * chat_message_payload_dake_key_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadDAKEKey *myPayload = payload;
	unsigned char *buf;
	unsigned int pos = 0;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_key_serialize: start\n");

	// 4 for recipient, TDH_MAC_LENGTH for mac, 4 for keylen, keylen for key
	*payload_size = 8 + TDH_MAC_LENGTH + myPayload->data.keylen;

	buf = malloc(*payload_size * sizeof *buf);
	if(!buf) { goto error; }

	chat_serial_int_to_string(myPayload->recipient, &buf[pos]);
	pos += 4;
	memcpy(&buf[pos], myPayload->data.mac, TDH_MAC_LENGTH);
	pos += TDH_MAC_LENGTH;
	chat_serial_int_to_string(myPayload->data.keylen, &buf[pos]);
	pos += 4;
	memcpy(&buf[pos], myPayload->data.key, myPayload->data.keylen);
	pos += myPayload->data.keylen;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_key_serialize: end\n");

	return buf;

error:
	return NULL;
}

MessagePayloadPtr chat_message_payload_dake_key_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadDAKEKey *payload;
	unsigned int pos = 0;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_key_parse: start\n");

	if(length < 8 + TDH_MAC_LENGTH) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_key_parse: before payload->recipient\n");
	payload->recipient = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_key_parse: before payload->data.mac\n");
	memcpy(payload->data.mac, &message[pos], TDH_MAC_LENGTH);
	pos += TDH_MAC_LENGTH;
	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_key_parse: before payload->data.keylen\n");
	payload->data.keylen = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	if(length != 8 + TDH_MAC_LENGTH + payload->data.keylen) { goto error_with_payload; }
	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_key_parse: before malloc\n");
	payload->data.key = malloc(payload->data.keylen * sizeof *(payload->data.key));
	if(!payload->data.key) { goto error_with_payload; }
	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_key_parse: before payload->data.key\n");
	memcpy(payload->data.key, &message[pos], payload->data.keylen);
	pos += payload->data.keylen;

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_dake_key_parse: end\n");

	return payload;

error_with_payload:
	free(payload);
error:
	return NULL;
}

void chat_message_payload_dake_key_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadDAKEKey *myPayload = payload;
	free(myPayload->data.key);
	free(myPayload);
}

MessagePayloadPtr chat_message_payload_gka_upflow_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadGKAUpflow *payload;

	unsigned int pos = 0;
	int keysLength, i, keySize;
	gcry_mpi_t *key;

	// TODO check length

	fprintf(stderr, "libotr-mpOTR: chat_message_payload_gka_upflow_parse: start\n");

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	payload->recipient = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	keysLength = chat_serial_string_to_int(&message[pos]);
	pos += 4;

	payload->interKeys = otrl_list_create(&interKeyOps, sizeof(gcry_mpi_t));
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
	OtrlChatMessagePayloadGKAUpflow *myPayload;
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

	// 4 recipient, 4 interkeys size header
	*payload_size += 8;

	ret = malloc(*payload_size * sizeof *ret);
	if(!ret) { goto error_with_filled_keys; }

	unsigned int pos = 0;

	chat_serial_int_to_string(myPayload->recipient, &ret[pos]);
	pos += 4;
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
	OtrlChatMessagePayloadGKAUpflow *myPayload = payload;

	otrl_list_destroy(myPayload->interKeys);
	free(myPayload);
}


MessagePayloadPtr chat_message_payload_gka_downflow_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadGKADownflow *payload;

	unsigned int pos = 0;
	int keysLength, i, keySize;
	gcry_mpi_t *key;

	// TODO check length

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	keysLength = chat_serial_string_to_int(&message[pos]);
	pos += 4;

	payload->interKeys = otrl_list_create(&interKeyOps, sizeof(gcry_mpi_t));
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
	OtrlChatMessagePayloadGKADownflow *myPayload;
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

	// 4 interkeys size header
	*payload_size += 4;

	ret = malloc(*payload_size * sizeof *ret);
	if(!ret) { goto error_with_filled_keys; }

	unsigned int pos = 0;
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
	OtrlChatMessagePayloadGKADownflow *myPayload = payload;

	otrl_list_destroy(myPayload->interKeys);
	free(myPayload);
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

void chat_message_free(OtrlChatMessage * msg)
{
	fprintf(stderr, "libotr-mpOTR: chat_message_free: start\n");
	if(msg) {
		if(msg->payload_free && msg->payload) {
			msg->payload_free(msg->payload);
		}
		free(msg->senderName);
		free(msg);
	}
	fprintf(stderr, "libotr-mpOTR: chat_message_free: end\n");
}

unsigned char chat_message_message_type_serialize(OtrlMessageType msgType)
{
	return ((unsigned char)msgType);
}

int chat_message_type_contains_sid(OtrlMessageType type)
{
	switch(type) {
		case OTRL_MSGTYPE_CHAT_DAKE_HANDSHAKE:
		case OTRL_MSGTYPE_CHAT_DAKE_CONFIRM:
		case OTRL_MSGTYPE_CHAT_GKA_UPFLOW:
		case OTRL_MSGTYPE_CHAT_GKA_DOWNFLOW:
		case OTRL_MSGTYPE_CHAT_DATA:
			return 1;
			break;
		case OTRL_MSGTYPE_CHAT_NOTOTR:
		case OTRL_MSGTYPE_CHAT_OFFER:
		default:
			return 0;
	}
}

int chat_message_type_should_be_signed(OtrlMessageType type)
{
	switch(type) {
		case OTRL_MSGTYPE_CHAT_GKA_UPFLOW:
		case OTRL_MSGTYPE_CHAT_GKA_DOWNFLOW:
		case OTRL_MSGTYPE_CHAT_DATA:
			return 1;
			break;
		case OTRL_MSGTYPE_CHAT_NOTOTR:
		case OTRL_MSGTYPE_CHAT_OFFER:
		case OTRL_MSGTYPE_CHAT_DAKE_HANDSHAKE:
		case OTRL_MSGTYPE_CHAT_DAKE_CONFIRM:
		default:
			return 0;
	}
}

unsigned char * chat_message_serialize(OtrlChatMessage *msg, size_t *length)
{
	//char *message;
	unsigned char *buf;
	size_t buflen, payloadlen;
	unsigned int pos = 0;

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: start\n");

	if(!msg || !msg->payload_serialize) { goto error; }

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before msg->payload_serialize\n");
	unsigned char *payload_serialized = msg->payload_serialize(msg->payload, &payloadlen);
	if(!payload_serialized) { goto error; }

	buflen = payloadlen + 11;
	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before chat_message_type_contains_sid\n");
	if(chat_message_type_contains_sid(msg->msgType)) {
		buflen += CHAT_OFFER_SID_LENGTH;
	}

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: before buf = malloc\n");
	buf = malloc(buflen * sizeof *buf);
	if(!buf) { goto error_with_payload_serialized; }

	chat_serial_int16_to_string(msg->protoVersion, &buf[pos]);
	pos += 2;
	buf[pos] = chat_message_message_type_serialize(msg->msgType);
	pos += 1;
	chat_serial_int_to_string((int)msg->senderInsTag, &buf[pos]);
	pos += 4;
	chat_serial_int_to_string((int)msg->chatInsTag, &buf[pos]);
	pos += 4;
	if(chat_message_type_contains_sid(msg->msgType)) {
		memcpy(&buf[pos], msg->sid, CHAT_OFFER_SID_LENGTH);
		pos += CHAT_OFFER_SID_LENGTH;
	}
	memcpy(&buf[pos], payload_serialized, payloadlen);
	pos += payloadlen;

	//fprintf(stderr, "libotr-mpOTR: chat_message_serialize: serialized message:\n");
	//for(unsigned int i = 0; i<buflen;i++) fprintf(stderr,"%02X",buf[i]); fprintf(stderr,"\n");

	//message = otrl_base64_otr_encode(buf, buflen);
	//if(!message) { goto error_with_buf; }

	//free(buf);
	free(payload_serialized);

	*length = buflen;

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: end\n");
	return buf;

//error_with_buf:
//	free(buf);
error_with_payload_serialized:
	free(payload_serialized);
error:
	return NULL;
}

int chat_message_payload_parse(OtrlChatMessage *msg, const unsigned char *message, size_t length)
{
	if(!msg) { goto error; }

	switch(msg->msgType) {
		case OTRL_MSGTYPE_CHAT_OFFER:
			msg->payload_free = chat_message_payload_offer_free;
			msg->payload_serialize = chat_message_payload_offer_serialize;
			msg->payload = chat_message_payload_offer_parse(message, length);
			if(!msg->payload) { goto error; }
			break;

		case OTRL_MSGTYPE_CHAT_DAKE_HANDSHAKE:
			msg->payload_free = chat_message_payload_dake_handshake_free;
			msg->payload_serialize = chat_message_payload_dake_handshake_serialize;
			msg->payload = chat_message_payload_dake_handshake_parse(message, length);
			if(!msg->payload) { goto error; }
			break;

		case OTRL_MSGTYPE_CHAT_DAKE_CONFIRM:
			msg->payload_free = chat_message_payload_dake_confirm_free;
			msg->payload_serialize = chat_message_payload_dake_confirm_serialize;
			msg->payload = chat_message_payload_dake_confirm_parse(message, length);
			if(!msg->payload) { goto error; }
			break;

		case OTRL_MSGTYPE_CHAT_DAKE_KEY:
			msg->payload_free = chat_message_payload_dake_key_free;
			msg->payload_serialize = chat_message_payload_dake_key_serialize;
			msg->payload = chat_message_payload_dake_key_parse(message, length);
			if(!msg->payload) { goto error; }
			break;

		case OTRL_MSGTYPE_CHAT_GKA_UPFLOW:
			msg->payload_free = chat_message_payload_gka_upflow_free;
			msg->payload_serialize = chat_message_payload_gka_upflow_serialize;
			msg->payload = chat_message_payload_gka_upflow_parse(message, length);
			if(!msg->payload) { goto error; }
			break;

		case OTRL_MSGTYPE_CHAT_GKA_DOWNFLOW:
			msg->payload_free = chat_message_payload_gka_downflow_free;
			msg->payload_serialize = chat_message_payload_gka_downflow_serialize;
			msg->payload = chat_message_payload_gka_downflow_parse(message, length);
			if(!msg->payload) { goto error; }
			break;

		case OTRL_MSGTYPE_CHAT_DATA:
			msg->payload_free = chat_message_payload_data_free;
			msg->payload_serialize = chat_message_payload_data_serialize;
			msg->payload = chat_message_payload_data_parse(message, length);
			if(!msg->payload) { goto error; }
			break;

		default:
			goto error;
	}

	return 0;

error:
	return 1;
}

int chat_message_parse_type(const unsigned char *message, const size_t messagelen, OtrlChatMessageType *type)
{
	if(messagelen < 3) { goto error; }
	//TODO maybe define a value for the position of message type
	*type = chat_message_message_type_parse(message[2]);
	return 0;

error:
	return 1;
}

OtrlChatMessage * chat_message_parse(const unsigned char *message, const size_t messagelen, const char *accountname)
{
	OtrlChatMessage *msg;
	//unsigned char *buf = NULL;
	//size_t buflen;
	unsigned int pos = 0;
	int err;

	fprintf(stderr, "libotr-mpOTR: chat_message_parse: start, accountname: %s\n", accountname);

	msg = malloc(sizeof *msg);
	if(!msg) { goto error; }

	// TODO Dimtiris: maybe not return a struct in this case?
	/*
	if(!chat_message_is_otr((char *)message)) {
		msg->protoVersion = 0;
		msg->msgType = OTRL_MSGTYPE_NOTOTR;
		msg->senderInsTag = 0;
		msg->chatInsTag = 0;
		msg->payload = NULL;
		msg->payload_free = NULL;
		msg->payload_serialize = NULL;
		return msg;
	}*/

	// TODO: handle this case
	//if(chat_message_is_fragment(message)) { goto error_with_msg; }

	//res = otrl_base64_otr_decode(message, &buf, &buflen);
	//if(res != 0 ) { goto error_with_msg; }

	if(messagelen < 11)	{ goto error_with_msg; }

	msg->protoVersion = chat_serial_string_to_int16(&message[pos]);
	pos += 2;
	msg->msgType = chat_message_message_type_parse(message[pos]);
	pos += 1;
	msg->senderInsTag = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	msg->chatInsTag = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	if(chat_message_type_contains_sid(msg->msgType)) {
		if(messagelen < 11 + CHAT_OFFER_SID_LENGTH) { goto error_with_msg; }
		memcpy(msg->sid, &message[pos], CHAT_OFFER_SID_LENGTH);
		pos += CHAT_OFFER_SID_LENGTH;
	}
	msg->senderName = strdup(accountname);
	err = chat_message_payload_parse(msg, &message[pos], messagelen-pos);
	if(err) { goto error_with_msg; }

	//free(buf);

	return msg;

//error_with_buf:
//	free(buf);
error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
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
	msg->senderName = strdup(ctx->accountname);
	if(chat_message_type_contains_sid(msgType)) {
		memcpy(msg->sid, ctx->sid, CHAT_OFFER_SID_LENGTH);
	}
	msg->payload = NULL;
	msg->payload_free = NULL;
	msg->payload_serialize = NULL;

	return msg;

error:
	return NULL;
}

OtrlChatMessage * chat_message_offer_create(OtrlChatContext *ctx, const unsigned char *sid_contribution, unsigned int position)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadOffer *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_OFFER);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	memcpy(payload->sid_contribution, sid_contribution, CHAT_OFFER_SID_CONTRIBUTION_LENGTH);
	payload->position = position;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_offer_free;
	msg->payload_serialize = chat_message_payload_offer_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

OtrlChatMessage * chat_message_dake_handshake_create(OtrlChatContext *ctx, DAKE_handshake_message_data *data)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadDAKEHandshake *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_DAKE_HANDSHAKE);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->handshake_data = *data;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_dake_handshake_free;
	msg->payload_serialize = chat_message_payload_dake_handshake_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

OtrlChatMessage * chat_message_dake_confirm_create(OtrlChatContext *ctx, unsigned int recipient, DAKE_confirm_message_data *data)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadDAKEConfirm *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_DAKE_CONFIRM);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->recipient = recipient;
	payload->data = *data;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_dake_confirm_free;
	msg->payload_serialize = chat_message_payload_dake_confirm_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

OtrlChatMessage * chat_message_dake_key_create(OtrlChatContext *ctx, unsigned int recipient, DAKE_key_message_data *data)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadDAKEKey *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_DAKE_KEY);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->recipient = recipient;
	payload->data = *data;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_dake_key_free;
	msg->payload_serialize = chat_message_payload_dake_key_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

OtrlChatMessage * chat_message_gka_upflow_create(OtrlChatContext *ctx, OtrlList *interKeys, unsigned int recipient)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadGKAUpflow *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_GKA_UPFLOW);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->interKeys = interKeys;
    // TODO fix this so that it adds the sid in the message
	//memcpy(payload->partlistHash, partlistHash, sizeof(payload->partlistHash));
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

OtrlChatMessage * chat_message_gka_downflow_create(OtrlChatContext *ctx, OtrlList *interKeys)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadGKADownflow *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_GKA_DOWNFLOW);
	if(!msg) {goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->interKeys = interKeys;
    //TODO fix this so that it add the sid in the message
	//memcpy(payload->partlistHash, partlistHash, sizeof(payload->partlistHash));

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


/*
int chat_message_send(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, OtrlChatMessage *msg)
{
	char *message, *token;
	unsigned char *buf;
	size_t buflen;
	int chat_flag = 1;

	fprintf(stderr, "libotr-mpOTR: chat_message_send: start\n");

	buf = chat_message_serialize(msg, &buflen);
	if(!buf) { goto error; }

	fprintf(stderr, "libotr-mpOTR: chat_message_send: before chat_message_type_should_be_signed\n");
	//if(chat_message_type_should_be_signed(msg->msgType) && ctx->sign_state == OTRL_CHAT_SINGSTATE_SINGED) {
		// TODO attach the sign to the serialized message and save it to *messagep
		//Signature *signature = chat_sign_sign(ctx->signing_key, buf, buflen);
	//}
	fprintf(stderr, "libotr-mpOTR: chat_message_send: before otrl_base64_otr_encode\n");
	message = otrl_base64_otr_encode(buf, buflen);
	if(!message) { goto error_with_buf; }

	// TODO Dimtiris: this is a work-around to pass the token as a recipient string. We should change that ASAP
	// 				  maybe define another callback with this prototype:
	//				  inject_chat_message(const char * accountname, const char *protocol, otrl_chat_token_t token, const char *message)
	token = malloc(sizeof(int));
	if(!token) { goto error_with_message; }

	memcpy(token, (char*)ctx->the_chat_token, sizeof(int));
	ops->inject_message(&chat_flag, ctx->accountname, ctx->protocol, token, message);

	free(token);
	free(buf);
	free(message);

	fprintf(stderr, "libotr-mpOTR: chat_message_send: end\n");

	return 0;

error_with_message:
	free(message);
error_with_buf:
	free(buf);
error:
	return 1;
}
*/
