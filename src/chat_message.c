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

/**
  Checks if a serialized message is an OTR message

  @param[in] message The message

  @return 1 if it's an OTR message, else 0.
 */
int chat_message_is_otr(const char * message)
{
	if(strstr(message, "?OTR") == message)
		return 1;
	else
		return 0;
}

/**
  Checks if a serialized message is an OTR message fragment

  @param[in] message The message

  @return 1 if it's an OTR message fragment, else 0.
 */
int chat_message_is_fragment(const char * message)
{
	if(strstr(message, "?OTR|") == message)
		return 1;
	else
		return 0;
}

/**
  Parses a serialized message type

  @param[in] c The byte containing the serialized message type

  @return The message type.
 */
OtrlChatMessageType chat_message_message_type_parse(unsigned char c)
{
	return (OtrlChatMessageType)c;	// TODO Dimitris: do the actual mapping
}

/**
  Serializes an offer message payload

  @param[in] 	payload 		A pointer to the payload
  @param[out] 	payload_size 	Returns the size of the serialized payload

  @return The serialized payload. NULL in case of error. Caller should free the
  	  	  returned string.
 */
unsigned char * chat_message_payload_offer_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadOffer *myPayload = payload;
	unsigned char *ret;
	unsigned int pos = 0;
	size_t len;

	len = 4 + CHAT_OFFER_SID_CONTRIBUTION_LENGTH;
	ret = malloc(len * sizeof *ret);
	if(!ret) { goto error; }

	chat_serial_int_to_string(myPayload->position, &ret[pos]);
	pos += 4;
	memcpy(&ret[pos], myPayload->sid_contribution, CHAT_OFFER_SID_CONTRIBUTION_LENGTH);
	pos += CHAT_OFFER_SID_CONTRIBUTION_LENGTH;

	*payload_size = len;
	return ret;

error:
	return NULL;
}

/**
  Parses a serialized offer message payload

  @param[in] message 	The serialized payload
  @param[in] length 	The length of the message string

  @return A pointer to the parsed payload. NULL in case of error. Caller should
  	  	  free the returned string using chat_message_payload_offer_free().
 */
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

/**
  Frees an offer message payload

  @param[in] payload The payload to be freed
 */
void chat_message_payload_offer_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadOffer *myPayload = payload;
	free(myPayload);
}

/**
  Serializes a DAKE handshake message payload

  @param[in] 	payload 		A pointer to the payload
  @param[out] 	payload_size 	Returns the size of the serialized payload

  @return The serialized payload. NULL in case of error. Caller should free the
  	  	  returned string.
 */
unsigned char * chat_message_payload_dake_handshake_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadDAKEHandshake *myPayload = payload;
	unsigned char *buf, *ephem_pub, *long_pub;
	unsigned int pos = 0;
	int err;
	size_t len, ephem_size, long_size;

	err = chat_serial_mpi_to_string(myPayload->handshake_data->ephem_pub, &ephem_pub, &ephem_size);
	if(err) { goto error; }
	err = chat_serial_mpi_to_string(myPayload->handshake_data->long_pub, &long_pub, &long_size);
	if(err) { goto error_with_ehpem_pub; }

	//4 for ephem_size, ephem_size for ephem_pub, 4 for long_size, long_size for long_pub
	len = 8 + ephem_size + long_size;
	buf = malloc(len * sizeof *buf);
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

	*payload_size = len;
	return buf;

error_with_long_pub:
	free(long_pub);
error_with_ehpem_pub:
	free(ephem_pub);
error:
	return NULL;
}

/**
  Parses a serialized DAKE handshake message payload

  @param[in] message 	The serialized payload
  @param[in] length 	The length of the message string

  @return A pointer to the parsed payload. NULL in case of error. Caller
  	  	  should free the returned string using
  	  	  chat_message_payload_dake_handshake_free().
 */
MessagePayloadPtr chat_message_payload_dake_handshake_parse(const unsigned char *message, size_t length)
{
	unsigned int pos = 0;
	OtrlChatMessagePayloadDAKEHandshake *payload;
	size_t ephem_size, long_size;

	if(length < 8) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }
	payload->handshake_data = malloc(sizeof *(payload->handshake_data));
	if(!payload->handshake_data) { goto error_with_payload; }


	ephem_size = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	if(length < 8 + ephem_size) { goto error_with_payload; }
	// TODO error handling for mpis
	chat_serial_string_to_mpi(&message[pos], &payload->handshake_data->ephem_pub, ephem_size);
	pos += ephem_size;
	long_size = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	if(length != 8 + ephem_size+ long_size) { goto error_with_payload; }
	chat_serial_string_to_mpi(&message[pos], &payload->handshake_data->long_pub, long_size);
	pos += long_size;

	return payload;

error_with_payload:
	free(payload);
error:
	return NULL;
}

/**
  Frees a DAKE Handshake message payload

  @param[in] payload The payload to be freed
 */
void chat_message_payload_dake_handshake_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadDAKEHandshake *myPayload = payload;
	//TODO Dimitris: Is that correct????
	gcry_mpi_release(myPayload->handshake_data->ephem_pub);
	gcry_mpi_release(myPayload->handshake_data->long_pub);
	free(myPayload->handshake_data);
	free(myPayload);
}

/**
  Serializes a DAKE Confirm message payload

  @param[in] 	payload 		A pointer to the payload
  @param[out] 	payload_size 	Returns the size of the serialized payload

  @return The serialized payload. NULL in case of error. Caller should free the
  	  	  returned string.
 */
unsigned char * chat_message_payload_dake_confirm_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadDAKEConfirm *myPayload = payload;
	unsigned char *buf;
	unsigned int pos = 0;
	size_t len;

	len = 4 + TDH_MAC_LENGTH;
	buf = malloc(len * sizeof *buf);
	if(!buf) { goto error; }

	chat_serial_int_to_string(myPayload->recipient, &buf[pos]);
	pos += 4;
	memcpy(&buf[pos], myPayload->data->mac, TDH_MAC_LENGTH);
	pos += TDH_MAC_LENGTH;

	*payload_size = len;
	return buf;

error:
	return NULL;
}

/**
  Parses a serialized DAKE confirm message payload

  @param[in] message 	The serialized payload
  @param[in] length 	The length of the message string

  @return A pointer to the parsed payload. NULL in case of error. Caller
  	  	  should free the returned string using
  	  	  chat_message_payload_dake_confirm_free().
 */
MessagePayloadPtr chat_message_payload_dake_confirm_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadDAKEConfirm *payload;
	unsigned int pos = 0;

	if(length != 4 + TDH_MAC_LENGTH) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }
	payload->data = malloc(sizeof *(payload->data));
	if(!payload->data) { goto error_with_payload; }

	payload->recipient = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	memcpy(payload->data->mac, &message[pos], TDH_MAC_LENGTH);
	pos += TDH_MAC_LENGTH;

	return payload;

error_with_payload:
	free(payload);
error:
	return NULL;
}

/**
  Frees a DAKE Confirm message payload

  @param[in] payload The payload to be freed
 */
void chat_message_payload_dake_confirm_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadDAKEConfirm *myPayload = payload;
	free(myPayload->data);
	free(myPayload);
}

/**
  Serializes a DAKE Key message payload

  @param[in] 	payload 		A pointer to the payload
  @param[out] 	payload_size 	Returns the size of the serialized payload

  @return The serialized payload. NULL in case of error. Caller should free the
  	  	  returned string.
 */
unsigned char * chat_message_payload_dake_key_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadDAKEKey *myPayload = payload;
	unsigned char *buf;
	unsigned int pos = 0;
	size_t len;

	// 4 for recipient, TDH_MAC_LENGTH for mac, 4 for keylen, keylen for key
	len = 8 + TDH_MAC_LENGTH + myPayload->data->keylen;

	buf = malloc(len * sizeof *buf);
	if(!buf) { goto error; }

	chat_serial_int_to_string(myPayload->recipient, &buf[pos]);
	pos += 4;
	memcpy(&buf[pos], myPayload->data->mac, TDH_MAC_LENGTH);
	pos += TDH_MAC_LENGTH;
	chat_serial_int_to_string(myPayload->data->keylen, &buf[pos]);
	pos += 4;
	memcpy(&buf[pos], myPayload->data->key, myPayload->data->keylen);
	pos += myPayload->data->keylen;

	*payload_size = len;
	return buf;

error:
	return NULL;
}

/**
  Parses a serialized DAKE Key message payload

  @param[in] message 	The serialized payload
  @param[in] length 	The length of the message string

  @return A pointer to the parsed payload. NULL in case of error. Caller
  	  	  should free the returned string using
  	  	  chat_message_payload_dake_key_free().
 */
MessagePayloadPtr chat_message_payload_dake_key_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadDAKEKey *payload;
	unsigned int pos = 0;

	if(length < 8 + TDH_MAC_LENGTH) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	payload->data = malloc(sizeof *(payload->data));
	if(!payload->data) { goto error_with_payload; }

	payload->recipient = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	memcpy(payload->data->mac, &message[pos], TDH_MAC_LENGTH);
	pos += TDH_MAC_LENGTH;
	payload->data->keylen = chat_serial_string_to_int(&message[pos]);
	pos += 4;

	if(length != 8 + TDH_MAC_LENGTH + payload->data->keylen) { goto error_with_payload_data; }

	payload->data->key = malloc(payload->data->keylen * sizeof *(payload->data->key));
	if(!payload->data->key) { goto error_with_payload; }
	memcpy(payload->data->key, &message[pos], payload->data->keylen);
	pos += payload->data->keylen;

	return payload;

error_with_payload_data:
	free(payload->data);
error_with_payload:
	free(payload);
error:
	return NULL;
}

/**
  Frees a DAKE Key message payload

  @param[in] payload The payload to be freed
 */
void chat_message_payload_dake_key_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadDAKEKey *myPayload = payload;

	free(myPayload->data->key);
	free(myPayload->data);
	free(myPayload);
}

/**
  Serializes a GKA Upflow payload

  @param[in] 	payload 		A pointer to the payload
  @param[out] 	payload_size 	Returns the size of the serialized payload

  @return The serialized payload. NULL in case of error. Caller should free the
  	  	  returned string.
 */
unsigned char * chat_message_payload_gka_upflow_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadGKAUpflow *myPayload = payload;
	unsigned char *ret, **keys;
	unsigned int i;
	int err;
	size_t *keySizes, len;
	gcry_mpi_t *k;
	OtrlListNode *cur;

	fprintf(stderr,"chat_message_payload_gka_upflow_serialize: start\n");

	otrl_list_dump(myPayload->interKeys);

	keys = malloc(myPayload->interKeys->size * sizeof *keys);
	if(!keys) { goto error; }

	for(i = 0; i < myPayload->interKeys->size; i++) {
		keys[i] = NULL;
	}

	keySizes = malloc(myPayload->interKeys->size * sizeof *keySizes);
	if(!keySizes) { goto error_with_keys; }

	len = 0;
	for(i = 0, cur = myPayload->interKeys->head; cur != NULL; i++, cur = cur->next) {
		k = cur->payload;
		err = chat_serial_mpi_to_string(*k, &keys[i], &keySizes[i]);
		if(err) { goto error_with_filled_keys; }
		len += keySizes[i] + 4;
	}

	// 4 recipient, 4 interkeys size header
	len += 8;

	ret = malloc(len * sizeof *ret);
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

	fprintf(stderr,"chat_message_payload_gka_upflow_serialize: serialized payload: ");
	for(unsigned int i=0; i<len; i++) fprintf(stderr, "%02X", ret[i]);
	fprintf(stderr,"\n");

	fprintf(stderr,"chat_message_payload_gka_upflow_serialize: end\n");

	*payload_size = len;
	return ret;

error_with_filled_keys:
	for(i=0; i<myPayload->interKeys->size; i++) { free(keys[i]); }
	free(keySizes);
error_with_keys:
	free(keys);
error:
	return NULL;
}

/**
  Parses a serialized GKA Upflow message payload

  @param[in] message 	The serialized payload
  @param[in] length 	The length of the message string

  @return A pointer to the parsed payload. NULL in case of error. Caller
  	  	  should free the returned string using
  	  	  chat_message_payload_gka_upflow_free().
 */
MessagePayloadPtr chat_message_payload_gka_upflow_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadGKAUpflow *payload;

	unsigned int pos = 0;
	int keysLength, i, keySize, err;
	gcry_mpi_t *key;

	// TODO check length
	if(length < 8) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	payload->recipient = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	keysLength = chat_serial_string_to_int(&message[pos]);
	pos += 4;

	payload->interKeys = otrl_list_create(&interKeyOps, sizeof(gcry_mpi_t));
	if(!payload->interKeys) { goto error_with_payload; }

	for(i=0; i<keysLength; i++) {
		if(length < pos + 4) { goto error_with_payload_interKeys; }

		keySize = chat_serial_string_to_int(&message[pos]);
		pos += 4;

		if(length < pos + keySize) { goto error_with_payload_interKeys; }

		key = malloc(sizeof *key);
		if(!key) { goto error_with_payload_interKeys; }
		// TODO Dimitris error handling every use of chat_serial_string to mpi
		err = chat_serial_string_to_mpi(&message[pos], key, keySize);
		if(err) {
			free(key);
			goto error_with_payload_interKeys;
		}
		pos += keySize;
		otrl_list_append(payload->interKeys, key);
	}

	if(length != pos ) { goto error_with_payload_interKeys; }

	return (MessagePayloadPtr)payload;

error_with_payload_interKeys:
	otrl_list_destroy(payload->interKeys);
error_with_payload:
	free(payload);
error:
	return NULL;
}

/**
  Frees a GKA Upflow message payload

  @param[in] payload The payload to be freed
 */
void chat_message_payload_gka_upflow_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadGKAUpflow *myPayload = payload;

	otrl_list_destroy(myPayload->interKeys);
	free(myPayload);
}

/**
  Serializes a GKA Downflow payload

  @param[in] 	payload 		A pointer to the payload
  @param[out] 	payload_size 	Returns the size of the serialized payload

  @return The serialized payload. NULL in case of error. Caller should free the
  	  	  returned string.
 */
unsigned char * chat_message_payload_gka_downflow_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadGKADownflow *myPayload = payload;
	unsigned char *ret, **keys;
	unsigned int i;
	int err;
	size_t *keySizes, len;
	gcry_mpi_t *k;
	OtrlListNode *cur;

	keys = malloc(myPayload->interKeys->size * sizeof *keys);
	if(!keys) { goto error; }

	for(i = 0; i < myPayload->interKeys->size; i++) {
		keys[i] = NULL;
	}

	keySizes = malloc(myPayload->interKeys->size * sizeof *keySizes);
	if(!keySizes) { goto error_with_keys; }

	len = 0;
	for(i = 0, cur = myPayload->interKeys->head; cur != NULL; i++, cur = cur->next) {
		k = cur->payload;
		err = chat_serial_mpi_to_string(*k, &keys[i], &keySizes[i]);
		if(err) { goto error_with_filled_keys;	}
		len += keySizes[i] + 4;
	}

	// 4 interkeys size header
	len += 4;

	ret = malloc(len * sizeof *ret);
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

	*payload_size = len;
	return ret;

error_with_filled_keys:
	for(i=0; i<myPayload->interKeys->size; i++) { free(keys[i]); }
	free(keySizes);
error_with_keys:
	free(keys);
error:
	return NULL;
}

/**
  Parses a serialized GKA Downflow message payload

  @param[in] message 	The serialized payload
  @param[in] length 	The length of the message string

  @return A pointer to the parsed payload. NULL in case of error. Caller
  	  	  should free the returned string using
  	  	  chat_message_payload_gka_downflow_free().
 */
MessagePayloadPtr chat_message_payload_gka_downflow_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadGKADownflow *payload;

	unsigned int pos = 0;
	int keysLength, i, keySize;
	gcry_mpi_t *key;

	if(length < 4) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	keysLength = chat_serial_string_to_int(&message[pos]);
	pos += 4;

	payload->interKeys = otrl_list_create(&interKeyOps, sizeof(gcry_mpi_t));
	if(!payload->interKeys) { goto error_with_payload; }

	for(i=0; i<keysLength; i++) {
		if(length < pos + 4) { goto error_with_payload_interKeys; }
		keySize = chat_serial_string_to_int(&message[pos]);
		pos += 4;

		if(length < pos + keySize) { goto error_with_payload_interKeys; }
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

/**
  Frees a GKA Downflow message payload

  @param[in] payload The payload to be freed
 */
void chat_message_payload_gka_downflow_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadGKADownflow *myPayload = payload;

	otrl_list_destroy(myPayload->interKeys);
	free(myPayload);
}


/**
  Serializes an Attest payload

  @param[in] 	payload 		A pointer to the payload
  @param[out] 	payload_size 	Returns the size of the serialized payload

  @return The serialized payload. NULL in case of error. Caller should free the
  	  	  returned string.
 */
unsigned char * chat_message_payload_attest_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	OtrlChatMessagePayloadAttest *myPayload = payload;
	unsigned char *buf;
	size_t len;
	unsigned int pos = 0;

	len = CHAT_OFFER_SID_LENGTH + CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH;
	buf = malloc(len * sizeof *buf);
	if(!buf) { goto error; }

	memcpy(&buf[pos], myPayload->sid, CHAT_OFFER_SID_LENGTH);
	pos += CHAT_OFFER_SID_LENGTH;
	memcpy(&buf[pos], myPayload->assoctable_hash, CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH);
	pos += CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH;

	*payload_size = len;
	return buf;

error:
	return NULL;
}

/**
  Parses a serialized Attest message payload

  @param[in] message 	The serialized payload
  @param[in] length 	The length of the message string

  @return A pointer to the parsed payload. NULL in case of error. Caller
  	  	  should free the returned string using
  	  	  chat_message_payload_attest_free().
 */
MessagePayloadPtr chat_message_payload_attest_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadAttest *payload;
	unsigned int pos = 0;

	if(length != CHAT_OFFER_SID_LENGTH + CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH) { goto error; }

	payload = malloc(sizeof *payload);

	memcpy(payload->sid, &message[pos], CHAT_OFFER_SID_LENGTH);
	pos += CHAT_OFFER_SID_LENGTH;
	memcpy(payload->assoctable_hash, &message[pos], CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH);
	pos += CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH;

	return (MessagePayloadPtr)payload;

error:
	return NULL;
}

/**
  Frees an Attest message payload

  @param[in] payload The payload to be freed
 */
void chat_message_payload_attest_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadAttest *myPayload = payload;
	free(myPayload);
}

/**
  Serializes a Data payload

  @param[in] 	payload 		A pointer to the payload
  @param[out] 	payload_size 	Returns the size of the serialized payload

  @return The serialized payload. NULL in case of error. Caller should free the
  	  	  returned string.
 */
unsigned char * chat_message_payload_data_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	unsigned char *buf;
	unsigned int pos = 0;
	OtrlChatMessagePayloadData *myPayload= payload;
	size_t len;

	// 8 bytes for ctr, 4 for datalen + datalen for data
	len = 12 + myPayload->datalen;
	buf = malloc(len * sizeof *buf);
	if(!buf) { goto error; }

	memcpy(&buf[pos], myPayload->ctr, 8);
	pos += 8;

	chat_serial_int_to_string((int)myPayload->datalen, &buf[pos]);
	pos += 4;
	memcpy(&buf[pos], myPayload->ciphertext, myPayload->datalen);
	pos += myPayload->datalen;

	*payload_size = len;
	return buf;

error:
	return NULL;
}

/**
  Parses a serialized Data message payload

  @param[in] message 	The serialized payload
  @param[in] length 	The length of the message string

  @return A pointer to the parsed payload. NULL in case of error. Caller
  	  	  should free the returned string using
  	  	  chat_message_payload_data_free().
 */
MessagePayloadPtr chat_message_payload_data_parse(const unsigned char *message, size_t length)
{
	OtrlChatMessagePayloadData *payload;
	unsigned int pos = 0;

	// 8 bytes for ctr, 4 for datalen
	if(length < 12) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }

	memcpy(payload->ctr, &message[pos], 8);
	pos += 8;

	payload->datalen = chat_serial_string_to_int(&message[pos]);
	pos += 4;

	if(length != pos + payload->datalen) { goto error_with_payload; }

	payload->ciphertext = malloc(payload->datalen * sizeof *(payload->ciphertext));
	if(!(payload->ciphertext)) { goto error_with_payload; }
	memcpy(payload->ciphertext, &message[pos], payload->datalen);
	pos += payload->datalen;

	return (MessagePayloadPtr)payload;

error_with_payload:
	free(payload);
error:
	return NULL;
}

/**
  Frees a Data message payload

  @param[in] payload The payload to be freed
 */
void chat_message_payload_data_free(MessagePayloadPtr payload)
{
	OtrlChatMessagePayloadData *myPayload= payload;

	if(myPayload) {
		if(myPayload->ciphertext) {
			free(myPayload->ciphertext);
		}
		free(myPayload);
	}
}

/**
  Serializes a Shutdown KeyRelease payload

  @param[in] 	payload 		A pointer to the payload
  @param[out] 	payload_size 	Returns the size of the serialized payload

  @return The serialized payload. NULL in case of error. Caller should free the
  	  	  returned string.
 */
unsigned char * chat_message_payload_shutdown_keyrelease_serialize(MessagePayloadPtr payload, size_t *payload_size)
{
	unsigned char *buf;
	unsigned int pos = 0;
	ChatMessagePayloadShutdownKeyRelease *myPayload= payload;
	size_t len;

	// 4 for keylen + keylen for key
	len = 4 + myPayload->keylen;
	buf = malloc(len * sizeof *buf);
	if(!buf) { goto error; }

	chat_serial_int_to_string((int)myPayload->keylen, &buf[pos]);
	pos += 4;
	memcpy(&buf[pos], myPayload->key, myPayload->keylen);
	pos += myPayload->keylen;

	*payload_size = len;
	return buf;

error:
	return NULL;
}

/**
  Parses a serialized Shutdown KeyRelease message payload

  @param[in] message 	The serialized payload
  @param[in] length 	The length of the message string

  @return A pointer to the parsed payload. NULL in case of error. Caller
  	  	  should free the returned string using
  	  	  chat_message_payload_shutdown_keyrelease_free().
 */
MessagePayloadPtr chat_message_payload_shutdown_keyrelease_parse(const unsigned char *message, size_t length)
{
	ChatMessagePayloadShutdownKeyRelease *payload;
	unsigned int pos = 0;

	// 4 for datalen
	if(length < 4) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error; }


	payload->keylen = chat_serial_string_to_int(&message[pos]);
	pos += 4;

	if(length != pos + payload->keylen) { goto error_with_payload; }

	payload->key = malloc(payload->keylen * sizeof *(payload->key));
	if(!(payload->key)) { goto error_with_payload; }
	memcpy(payload->key, &message[pos], payload->keylen);
	pos += payload->keylen;

	return (MessagePayloadPtr)payload;

error_with_payload:
	free(payload);
error:
	return NULL;
}

/**
  Frees a Shutdown KeyRelease message payload

  @param[in] payload The payload to be freed
 */
void chat_message_payload_shutdown_keyrelease_free(MessagePayloadPtr payload)
{
	ChatMessagePayloadShutdownKeyRelease *myPayload= payload;

	if(myPayload) {
		if(myPayload->key) {
			free(myPayload->key);
		}
		free(myPayload);
	}
}

void chat_message_free(OtrlChatMessage * msg)
{
	if(msg) {
		if(msg->payload_free && msg->payload) {
			msg->payload_free(msg->payload);
		}
		free(msg->senderName);
		free(msg);
	}
}

unsigned char chat_message_message_type_serialize(OtrlChatMessageType msgType)
{
	return ((unsigned char)msgType);
}

int chat_message_type_contains_sid(OtrlChatMessageType type)
{
	switch(type) {
		case OTRL_MSGTYPE_CHAT_NOTOTR:
		case OTRL_MSGTYPE_CHAT_OFFER:
			return 0;
			break;
		default:
			return 1;

	}
}

int chat_message_type_should_be_signed(OtrlChatMessageType type)
{
	switch(type) {
		case OTRL_MSGTYPE_CHAT_NOTOTR:
		case OTRL_MSGTYPE_CHAT_OFFER:
		case OTRL_MSGTYPE_CHAT_DAKE_HANDSHAKE:
		case OTRL_MSGTYPE_CHAT_DAKE_CONFIRM:
		case OTRL_MSGTYPE_CHAT_DAKE_KEY:
			return 0;
			break;
		default:
			return 1;
	}
}

unsigned char * chat_message_serialize(OtrlChatMessage *msg, size_t *length)
{
	//char *message;
	unsigned char *buf, *payload_serialized = NULL;
	size_t buflen, payloadlen = 0;
	unsigned int pos = 0;

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: start\n");

	if(!msg) { goto error; }

	if(msg->payload_serialize && msg->payload) {
		payload_serialized = msg->payload_serialize(msg->payload, &payloadlen);
		if(!payload_serialized) { goto error; }
	}

	buflen = payloadlen + 11;
	if(chat_message_type_contains_sid(msg->msgType)) {
		buflen += CHAT_OFFER_SID_LENGTH;
	}

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

	if(payload_serialized) {
		memcpy(&buf[pos], payload_serialized, payloadlen);
		pos += payloadlen;
		free(payload_serialized);
	}

	fprintf(stderr, "libotr-mpOTR: chat_message_serialize: end\n");

	*length = buflen;
	return buf;

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

		case OTRL_MSGTYPE_CHAT_ATTEST:
			msg->payload_free = chat_message_payload_attest_free;
			msg->payload_serialize = chat_message_payload_attest_serialize;
			msg->payload = chat_message_payload_attest_parse(message, length);
			if(!msg->payload) { goto error; }
			break;

		case OTRL_MSGTYPE_CHAT_DATA:
			msg->payload_free = chat_message_payload_data_free;
			msg->payload_serialize = chat_message_payload_data_serialize;
			msg->payload = chat_message_payload_data_parse(message, length);
			if(!msg->payload) { goto error; }
			break;

		case OTRL_MSGTYPE_CHAT_SHUTDOWN_END:
			msg->payload_free = NULL;
			msg->payload_serialize = NULL;
			msg->payload = NULL;
			break;

		case OTRL_MSGTYPE_CHAT_SHUTDOWN_KEYRELEASE:
			msg->payload_free = chat_message_payload_shutdown_keyrelease_free;
			msg->payload_serialize = chat_message_payload_shutdown_keyrelease_serialize;
			msg->payload = chat_message_payload_shutdown_keyrelease_parse(message, length);
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
	unsigned int pos = 0;
	int err;

	if(messagelen < 11)	{ goto error; }

	msg = malloc(sizeof *msg);
	if(!msg) { goto error; }

	msg->senderName = NULL;
	msg->senderName = strdup(accountname);
	if(!msg->senderName) { goto error_with_msg; }

	msg->protoVersion = chat_serial_string_to_int16(&message[pos]);
	pos += 2;
	msg->msgType = chat_message_message_type_parse(message[pos]);
	pos += 1;
	msg->senderInsTag = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	msg->chatInsTag = chat_serial_string_to_int(&message[pos]);
	pos += 4;
	if(chat_message_type_contains_sid(msg->msgType)) {
		if(messagelen < pos + CHAT_OFFER_SID_LENGTH) { goto error_with_msg; }
		memcpy(msg->sid, &message[pos], CHAT_OFFER_SID_LENGTH);
		pos += CHAT_OFFER_SID_LENGTH;
	}
	err = chat_message_payload_parse(msg, &message[pos], messagelen-pos);
	if(err) { goto error_with_msg; }

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

/**
  Creates a new Chat Message with an empty payload

  @param[in] ctx 		The Context in which the message is created
  @param[in] msgType 	The message type

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
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
	if(!msg->senderName) { goto error_with_msg; }
	if(chat_message_type_contains_sid(msgType)) {
		memcpy(msg->sid, ctx->sid, CHAT_OFFER_SID_LENGTH);
	}
	msg->payload = NULL;
	msg->payload_free = NULL;
	msg->payload_serialize = NULL;

	return msg;

error_with_msg:
	free(msg);
error:
	return NULL;
}

/**
  Creates a new Offer message

  @param[in] ctx 				The Context in which the message is created
  @param[in] sid_contribution 	The sender's sid_contribution, used be value
  @param[in] position 			The sender's index in the participants list

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
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

/**
  Creates a new DAKE Handshake message

  @param[in] ctx 	The Context in which the message is created
  @param[in] data 	A pointer to the list containing the DAKE Handshake message
  	  	  	  	  	data, used by reference

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
OtrlChatMessage * chat_message_dake_handshake_create(OtrlChatContext *ctx, DAKE_handshake_message_data *data)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadDAKEHandshake *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_DAKE_HANDSHAKE);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->handshake_data = data;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_dake_handshake_free;
	msg->payload_serialize = chat_message_payload_dake_handshake_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

/**
  Creates a new DAKE Confirm message

  @param[in] ctx 		The Context in which the message is created
  @param[in] recipient 	The index of the participant the message is intended for
  @param[in] data 		A pointer to the list containing the DAKE Confirm
						message data, used by reference

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
OtrlChatMessage * chat_message_dake_confirm_create(OtrlChatContext *ctx, unsigned int recipient, DAKE_confirm_message_data *data)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadDAKEConfirm *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_DAKE_CONFIRM);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->recipient = recipient;
	payload->data = data;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_dake_confirm_free;
	msg->payload_serialize = chat_message_payload_dake_confirm_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

/**
  Creates a new DAKE Key message

  @param[in] ctx 		The Context in which the message is created
  @param[in] recipient 	The index of the participant the message is intended for
  @param[in] data 		A pointer to the list containing the DAKE Key message
						data, used by reference

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
OtrlChatMessage * chat_message_dake_key_create(OtrlChatContext *ctx, unsigned int recipient, DAKE_key_message_data *data)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadDAKEKey *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_DAKE_KEY);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->recipient = recipient;
	payload->data = data;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_dake_key_free;
	msg->payload_serialize = chat_message_payload_dake_key_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

/**
  Creates a new GKA Upflow message

  @param[in] ctx 		The Context in which the message is created
  @param[in] interKeys 	A pointer to the list containing the intermediate keys,
						used by reference
  @param[in] recipient 	The index of the participant the message is intended
						for

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
OtrlChatMessage * chat_message_gka_upflow_create(OtrlChatContext *ctx, OtrlList *interKeys, unsigned int recipient)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadGKAUpflow *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_GKA_UPFLOW);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->interKeys = interKeys;
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

/**
  Creates a new GKA Downflow message

  @param[in] ctx 		The Context in which the message is created
  @param[in] interKeys 	A pointer to the list containing the intermediate keys,
						used by reference

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
OtrlChatMessage * chat_message_gka_downflow_create(OtrlChatContext *ctx, OtrlList *interKeys)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadGKADownflow *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_GKA_DOWNFLOW);
	if(!msg) {goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->interKeys = interKeys;

	msg->payload = payload;
	msg->payload_free = chat_message_payload_gka_downflow_free;
	msg->payload_serialize = chat_message_payload_gka_downflow_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

/**
  Creates a new Attest message

  @param[in] ctx 				The Context in which the message is created
  @param[in] sid 				The sessionId, used by value
  @param[in] assoctable_hash 	The Association Table hash, used by value

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
OtrlChatMessage * chat_message_attest_create(OtrlChatContext *ctx, unsigned char *sid, unsigned char *assoctable_hash)
{
	OtrlChatMessage *msg;
	OtrlChatMessagePayloadAttest *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_ATTEST);
	if(!msg) {goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	memcpy(payload->sid, sid, CHAT_OFFER_SID_LENGTH);
	memcpy(payload->assoctable_hash, assoctable_hash, CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH);

	msg->payload = payload;
	msg->payload_free = chat_message_payload_attest_free;
	msg->payload_serialize = chat_message_payload_attest_serialize;

	return msg;

error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}

/**
  Creates a new data message

  @param[in] ctx 		The Context in which the message is created
  @param[in] ctr 		The AES counter
  @param[in] datalen 	The number of bytes contained in ciphertext
  @param[in] ciphertext The encrypted message. Used by reference

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
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

/**
  Creates a new Shutdown End message

  @param[in] ctx 		The Context in which the message is created

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
OtrlChatMessage * chat_message_shutdown_end_create(OtrlChatContext *ctx)
{
	OtrlChatMessage *msg;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_SHUTDOWN_END);
	if(!msg) { goto error; }

	msg->payload = NULL;
	msg->payload_free = NULL;
	msg->payload_serialize = NULL;

	return msg;

error:
	return NULL;
}

/**
  Creates a new Shutdown KeyRelease message

  @param[in] ctx 		The Context in which the message is created
  @param[in] keylen 	The number of bytes contained in key
  @param[in] key 		The key to be released. Used by value

  @return A pointer to the message created. NULL in case of error. Caller
  	  	  should free the returned message using the chat_message_free()
  	  	  function.
 */
OtrlChatMessage * chat_message_shutdown_keyrelease_create(OtrlChatContext *ctx, unsigned char *key, size_t keylen)
{
	OtrlChatMessage *msg;
	ChatMessagePayloadShutdownKeyRelease *payload;

	msg = chat_message_create(ctx, OTRL_MSGTYPE_CHAT_SHUTDOWN_KEYRELEASE);
	if(!msg) { goto error; }

	payload = malloc(sizeof *payload);
	if(!payload) { goto error_with_msg; }

	payload->keylen = keylen;

	payload->key = malloc(payload->keylen * sizeof *(payload->key));
	if(!payload->key) { goto error_with_payload; }
	memcpy(payload->key, key, keylen);

	msg->payload = payload;
	msg->payload_free = chat_message_payload_shutdown_keyrelease_free;
	msg->payload_serialize = chat_message_payload_shutdown_keyrelease_serialize;

	return msg;

error_with_payload:
	free(payload);
error_with_msg:
	chat_message_free(msg);
error:
	return NULL;
}
