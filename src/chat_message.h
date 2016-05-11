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

#ifndef CHAT_MESSAGE_H_
#define CHAT_MESSAGE_H_

#include <stdlib.h>

#include "tlv.h"
#include "proto.h"
#include "message.h"
#include "instag.h"
//#include "chat_token.h"
//#include "chat_context.h"

#include "chat_types.h"
/*
typedef void * MessagePayloadPtr;

typedef struct OtrlChatMessageStruct {
	int16_t protoVersion;
	OtrlMessageType msgType;
	otrl_instag_t senderInsTag;
	otrl_instag_t chatInsTag;
	MessagePayloadPtr payload;
	void (*payload_free)(MessagePayloadPtr);
	void (*payload_serialize)(MessagePayloadPtr);
} OtrlChatMessage;

typedef struct OtrlChatMessagePayloadQueryStruct {
	//TODO this is to change
	unsigned char key[32];
} OtrlChatMessagePayloadQuery;

typedef struct OtrlChatMessagePayloadQueryAckStruct {
	//TODO this is to change
	unsigned char magicnum[4];
} OtrlChatMessagePayloadQueryAck;

typedef struct OtrlChatMessagePayloadDataStruct {
	unsigned char ctr[8];
	int32_t datalen;
	unsigned char *ciphertext;
} OtrlChatMessagePayloadData;
*/


int otrl_chat_message_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *sender, otrl_chat_token_t chat_token, const char *message,
	char **newmessagep,	OtrlTLV **tlvsp);

int otrl_chat_message_sending(OtrlUserState us,
	const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *message, otrl_chat_token_t chat_token, OtrlTLV *tlvs,
	char **messagep, OtrlFragmentPolicy fragPolicy);

int otrl_chat_message_send_query(OtrlUserState us,
		const OtrlMessageAppOps *ops,
		const char *accountname, const char *protocol,
		otrl_chat_token_t chat_token, OtrlFragmentPolicy fragPolicy);

OtrlChatMessage * chat_message_parse(const char *message);

int chat_message_payload_parse(OtrlChatMessage *msg, const unsigned char *message, size_t length);

char * chat_message_serialize(OtrlChatMessage *msg);

MessagePayloadPtr chat_message_payload_data_parse(const unsigned char *message, size_t length);

void chat_message_payload_data_free(MessagePayloadPtr payload);

unsigned char * chat_message_payload_data_serialize(MessagePayloadPtr payload, size_t *payload_size);

OtrlMessageType chat_message_message_type_parse(unsigned char c);

unsigned char chat_message_message_type_serialize(OtrlMessageType msgType);
void chat_message_free(OtrlChatMessage * msg);

int chat_message_is_otr(const char * message);

int chat_message_is_fragment(const char * message);

OtrlChatMessage * chat_message_create(OtrlChatContext *ctx, OtrlChatMessageType msgType);

MessagePayloadPtr chat_message_payload_gka_upflow_parse(const unsigned char *message, size_t length);

unsigned char * chat_message_payload_gka_upflow_serialize(MessagePayloadPtr payload, size_t *payload_size);

void chat_message_payload_gka_upflow_free(MessagePayloadPtr payload);

MessagePayloadPtr chat_message_payload_gka_downflow_parse(const unsigned char *message, size_t length);

unsigned char * chat_message_payload_gka_downflow_serialize(MessagePayloadPtr payload, size_t *payload_size);

void chat_message_payload_gka_downflow_free(MessagePayloadPtr payload);

OtrlChatMessage * chat_message_gka_upflow_create(OtrlChatContext *ctx, const unsigned char *partlistHash, OtrlList *interKeys, unsigned int recipient);

OtrlChatMessage * chat_message_gka_downflow_create(OtrlChatContext *ctx, const unsigned char *partlistHash, OtrlList *interKeys);

OtrlChatMessage * chat_message_data_create(OtrlChatContext *ctx, unsigned char *ctr, size_t datalen, unsigned char *ciphertext);

int chat_message_send(const OtrlMessageAppOps *ops, OtrlChatContext *ctx, OtrlChatMessage *msg);

#endif /* CHAT_MESSAGE_H_ */
