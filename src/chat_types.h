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

#ifndef CHAT_TYPES_H
#define CHAT_TYPES_H

#include <stddef.h>
#include <stdint.h>

#include "context.h"

#define CHAT_PROTOCOL_VERSION 1

#define CHAT_PARTICIPANTS_HASH_LENGTH 64
#define CHAT_SECRET_LENGTH 64

#define CHAT_OFFER_SID_CONTRIBUTION_LENGTH 32
#define CHAT_OFFER_SID_LENGTH 64

#define CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH 64

#include "proto.h"
#include "tlv.h"
#include "dh.h"
#include "instag.h"
#include "chat_dake.h"
#include "chat_fingerprint.h"
#include "chat_idkey.h"
#include "chat_sign.h"
#include "list.h"

#include <gcrypt.h>

/* Chat Message type declerations */

typedef enum {
	CHAT_MSGTYPE_NOTOTR,
	CHAT_MSGTYPE_OFFER,
	CHAT_MSGTYPE_DAKE_HANDSHAKE,
	CHAT_MSGTYPE_DAKE_CONFIRM,
	CHAT_MSGTYPE_DAKE_KEY,
    CHAT_MSGTYPE_GKA_UPFLOW,
    CHAT_MSGTYPE_GKA_DOWNFLOW,
    CHAT_MSGTYPE_ATTEST,
    CHAT_MSGTYPE_DATA,
    CHAT_MSGTYPE_SHUTDOWN_SHUTDOWN,
    CHAT_MSGTYPE_SHUTDOWN_DIGEST,
    CHAT_MSGTYPE_SHUTDOWN_END,
    CHAT_MSGTYPE_SHUTDOWN_KEYRELEASE
} ChatMessageType;

typedef void * ChatMessagePayloadPtr;

typedef struct ChatMessageStruct {
		int16_t protoVersion;
		ChatMessageType msgType;
		otrl_instag_t senderInsTag;
		otrl_instag_t chatInsTag;
		char *senderName;
		unsigned char sid[CHAT_OFFER_SID_LENGTH];
		ChatMessagePayloadPtr payload;
		void (*payload_free)(ChatMessagePayloadPtr);
		unsigned char * (*payload_serialize)(ChatMessagePayloadPtr, size_t *);
} ChatMessage;

typedef struct ChatMessagePayloadOfferStruct {
        unsigned char sid_contribution[CHAT_OFFER_SID_CONTRIBUTION_LENGTH];
        unsigned int position;
} ChatMessagePayloadOffer;

typedef struct ChatMessagePayloadDAKEHandshakeStruct {
		DAKE_handshake_message_data *handshake_data;
} ChatMessagePayloadDAKEHandshake;

typedef struct ChatMessagePayloadDAKEConfirmStruct {
		unsigned int recipient;
		DAKE_confirm_message_data *data;
} ChatMessagePayloadDAKEConfirm;

typedef struct ChatMessagePayloadDAKEKeyStruct {
		unsigned int recipient;
		DAKE_key_message_data *data;
} ChatMessagePayloadDAKEKey;

typedef struct ChatMessagePayloadGKAUpflowStruct {
		unsigned int recipient;
		OtrlList interKeys;
} ChatMessagePayloadGKAUpflow;

typedef struct ChatMessagePayloadGKADownflowStruct {
		OtrlList interKeys;
} ChatMessagePayloadGKADownflow;

typedef struct ChatMessagePayloadAttestStruct {
		unsigned char sid[CHAT_OFFER_SID_LENGTH];
		unsigned char assoctable_hash[CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH];
} ChatMessagePayloadAttest;

typedef struct ChatMessagePayloadDataStruct {
        unsigned char ctr[8];
        size_t datalen;
        unsigned char *ciphertext;
} ChatMessagePayloadData;

typedef struct ChatMessagePayloadShutdownShutdownStruct {
	unsigned char shutdown_hash[CHAT_PARTICIPANTS_HASH_LENGTH];
} ChatMessagePayloadShutdownShutdown;

typedef struct ChatMessagePayloadShutdownDigestStruct {
	unsigned char digest[CHAT_PARTICIPANTS_HASH_LENGTH];
} ChatMessagePayloadShutdownDigest;

typedef struct ChatMessagePayloadShutdownKeyReleaseStruct {
		size_t keylen;
		unsigned char *key;
} ChatMessagePayloadShutdownKeyRelease;

typedef struct ChatOfferInfoStruct * ChatOfferInfo;
typedef struct ChatDSKEInfoStruct * ChatDSKEInfo;
typedef struct ChatGKAInfoStruct * ChatGKAInfo;
typedef struct ChatAttestInfoStruct * ChatAttestInfo;
typedef struct ChatShutdownInfoStruct * ChatShutdownInfo;

typedef int otrl_chat_token_t;

typedef enum {
	CHAT_SIGNSTATE_NONE,
	CHAT_SIGNSTATE_SIGNED
} ChatSignState;

typedef struct ChatEncInfoStruct {
        unsigned char ctr[16];	/* our counter */
        unsigned char *key;	/* the shared secret */
} ChatEncInfo;

typedef struct ChatContextStruct * ChatContext;

#endif /* CHAT_TYPES_H */
