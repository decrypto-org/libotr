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
#include "chat_idkey.h"
#include "chat_dake.h"
#include "chat_sign.h"
#include "chat_fingerprint.h"
//#include "chat_sign.h"

#include <gcrypt.h>

/* Chat Message type declerations */

typedef enum {
	OTRL_MSGTYPE_CHAT_NOTOTR,
	OTRL_MSGTYPE_CHAT_OFFER,
	OTRL_MSGTYPE_CHAT_DAKE_HANDSHAKE,
	OTRL_MSGTYPE_CHAT_DAKE_CONFIRM,
	OTRL_MSGTYPE_CHAT_DAKE_KEY,
    OTRL_MSGTYPE_CHAT_GKA_UPFLOW,
    OTRL_MSGTYPE_CHAT_GKA_DOWNFLOW,
    OTRL_MSGTYPE_CHAT_ATTEST,
    OTRL_MSGTYPE_CHAT_DATA,
    OTRL_MSGTYPE_CHAT_SHUTDOWN_END,
    OTRL_MSGTYPE_CHAT_SHUTDOWN_KEYRELEASE
} OtrlChatMessageType;

typedef void * MessagePayloadPtr;

typedef struct OtrlChatMessageStruct {
		int16_t protoVersion;
		OtrlChatMessageType msgType;
		otrl_instag_t senderInsTag;
		otrl_instag_t chatInsTag;
		char *senderName;
		//TODO typedef the sid type, and maybe implement methods to be used on sid
		unsigned char sid[CHAT_OFFER_SID_LENGTH];
		MessagePayloadPtr payload;
		void (*payload_free)(MessagePayloadPtr);
		unsigned char * (*payload_serialize)(MessagePayloadPtr, size_t *);
} OtrlChatMessage;

typedef struct OtrlChatMessagePayloadOfferStruct {
        unsigned char sid_contribution[CHAT_OFFER_SID_CONTRIBUTION_LENGTH];
        unsigned int position;
} OtrlChatMessagePayloadOffer;

typedef struct OtrlChatMessagePayloadDAKEHandshakeStruct {
		DAKE_handshake_message_data *handshake_data;
} OtrlChatMessagePayloadDAKEHandshake;

typedef struct OtrlChatMessagePayloadDAKEConfirmStruct {
		unsigned int recipient;
		DAKE_confirm_message_data *data;
} OtrlChatMessagePayloadDAKEConfirm;

typedef struct OtrlChatMessagePayloadDAKEKeyStruct {
		unsigned int recipient;
		DAKE_key_message_data *data;
} OtrlChatMessagePayloadDAKEKey;

typedef struct OtrlChatMessagePayloadGKAUpflowStruct {
		unsigned int recipient;
		OtrlList *interKeys;
} OtrlChatMessagePayloadGKAUpflow;

typedef struct OtrlChatMessagePayloadGKADownflowStruct {
		OtrlList *interKeys;
} OtrlChatMessagePayloadGKADownflow;

typedef struct OtrlChatMessagePayloadAttestStruct {
		unsigned char sid[CHAT_OFFER_SID_LENGTH];
		unsigned char assoctable_hash[CHAT_ATTEST_ASSOCTABLE_HASH_LENGTH];
} OtrlChatMessagePayloadAttest;

typedef struct OtrlChatMessagePayloadDataStruct {
        unsigned char ctr[8];
        size_t datalen;
        unsigned char *ciphertext;
} OtrlChatMessagePayloadData;

typedef struct ChatMessagePayloadShutdownKeyReleaseStruct {
		size_t keylen;
		unsigned char *key;
} ChatMessagePayloadShutdownKeyRelease;

typedef enum {
	OTRL_CHAT_OFFERSTATE_NONE,
	OTRL_CHAT_OFFERSTATE_AWAITING,
	OTRL_CHAT_OFFERSTATE_FINISHED
} OtrlChatOfferState;

typedef struct OtrlChatOfferInfoStruct {
		size_t size;
		size_t added;
		unsigned char **sid_contributions;
		OtrlChatOfferState state;
} OtrlChatOfferInfo;

typedef enum {
    OTRL_CHAT_ATTESTSTATE_NONE,
    OTRL_CHAT_ATTESTSTATE_AWAITING,
    OTRL_CHAT_ATTESTSTATE_FINISHED
} OtrlChatAttestState;

typedef struct OtrlChatAttestInfoStruct {
	size_t size;
	size_t checked_count;
	unsigned short int *checked;
	OtrlChatAttestState state;
} OtrlChatAttestInfo;

typedef enum {
	OTRL_CHAT_SINGSTATE_NONE,
	OTRL_CHAT_SINGSTATE_SINGED
} OtrlChatSignState;

/* Chat encryption type declarations */
typedef struct ChatEncInfoStruct {
        unsigned char ctr[16];    /* our counter */

        // TODO this should probably be a pointer since
        // this needs to be on secure memory. We can't
        // have secure memory with static allocation,
        // and allocating the whole struct in secure memory
        // would be a waste of resources.
        unsigned char *key;   //[32];
} OtrlChatEncInfo;


typedef enum {
	OTRL_CHAT_DSKESTATE_NONE,
	OTRL_CHAT_DSKESTATE_AWAITING_KEYS,
	OTRL_CHAT_DSKESTATE_FINISHED
} OtrlChatDSKEState;

/* Chat auth type declaration */
typedef enum {
        OTRL_CHAT_GKASTATE_NONE,
        OTRL_CHAT_GKASTATE_AWAITING_UPFLOW,
        OTRL_CHAT_GKASTATE_AWAITING_DOWNFLOW,
        OTRL_CHAT_GKASTATE_FINISHED
} OtrlChatGKAState;

typedef struct {
        OtrlChatGKAState state;  /* the gka state */

        unsigned int position;      /* Our position in the participants order starting from the gka initiator */

        DH_keypair *keypair;		/* The keypair used for the gka */

        unsigned char participants_hash[CHAT_PARTICIPANTS_HASH_LENGTH];
} OtrlAuthGKAInfo;


typedef struct {
	OtrlChatDSKEState state;

	DAKEInfo dake_info;

	unsigned int remaining;
} OtrlAuthDSKEInfo;

typedef enum {
	SHUTDOWN_WAITING_END,
	SHUTDOWN_FINISHED
} ShutdownState;

typedef struct {
	ShutdownState state;

} Shutdown;

typedef enum {
	OTRL_CHAT_SHUTDOWNSTATE_NONE,
	OTRL_CHAT_SHUTDOWNSTATE_AWAITING_ENDS,
	OTRL_CHAT_SHUTDOWNSTATE_FINISHED
} OtrlChatShutdownState;

typedef struct {
	int remaining;
	unsigned char *has_send_end;
	OtrlChatShutdownState state;
} OtrlShutdownInfo;

/* Chat token type declerations */
typedef char* otrl_chat_token_t;


/* Chat context type declerations */
typedef struct OtrlChatContextStruct {
        /* Context information that is meant for application use */

        char * accountname;                /* The username is relative to this account... */
        char * protocol;                   /* ... and this protocol */

        unsigned int id;				   /* Our id in this chat */

        otrl_instag_t our_instance;        /* Our instance tag for this computer*/
        otrl_chat_token_t the_chat_token;  /* The token of the chat */

        OtrlList *participants_list;       /* The users in this chatroom */

        OtrlChatOfferInfo *offer_info;

        OtrlChatAttestInfo *attest_info;

        OtrlChatEncInfo enc_info;          /* Info needed for encrypting messages */

        OtrlAuthGKAInfo gka_info;          /* Info needed for the GKA */

        OtrlAuthDSKEInfo *dske_info;	  	   /* Info needed for the DSKE */

        OtrlShutdownInfo shutdown_info;

        OtrlMessageState msg_state;

        OtrlChatSignState sign_state;

        SignKey *signing_key;		   /* The signing key */
        ChatIdKey *identity_key;
		unsigned char sid[CHAT_OFFER_SID_LENGTH];

        unsigned int protocol_version;     /* The version of OTR in use */

        /* Application data to be associated with this context */
        void *app_data;
        /* A function to free the above data when we forget this context */
        void (*app_data_free)(void *);
} OtrlChatContext;


typedef  struct OtrlChatParticipantStruct {
        char *username; // This users username
        OtrlChatMessage *pending_message; // A stored message by this user
        unsigned char *pending_signed_message;
        SignKey *sign_key; //This users signing key
        ChatFingerprint *fingerprint;
        DAKE *dake;
	Shutdown *shutdown;

} OtrlChatParticipant;

#endif /* CHAT_TYPES_H */
