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
#include "list.h"
//#include "chat_sign.h"

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
		//TODO typedef the sid type, and maybe implement methods to be used on sid
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
		OtrlList *interKeys;
} ChatMessagePayloadGKAUpflow;

typedef struct ChatMessagePayloadGKADownflowStruct {
		OtrlList *interKeys;
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

typedef struct ChatMessagePayloadShutdownKeyReleaseStruct {
		size_t keylen;
		unsigned char *key;
} ChatMessagePayloadShutdownKeyRelease;

typedef enum {
	CHAT_OFFERSTATE_NONE,
	CHAT_OFFERSTATE_AWAITING,
	CHAT_OFFERSTATE_FINISHED
} ChatOfferState;

typedef struct ChatOfferInfoStruct {
		size_t size;
		size_t added;
		unsigned char **sid_contributions;
		ChatOfferState state;
} ChatOfferInfo;

typedef enum {
    CHAT_ATTESTSTATE_NONE,
    CHAT_ATTESTSTATE_AWAITING,
    CHAT_ATTESTSTATE_FINISHED
} ChatAttestState;

typedef struct ChatAttestInfoStruct {
	size_t size;
	size_t checked_count;
	unsigned short int *checked;
	ChatAttestState state;
} ChatAttestInfo;

typedef enum {
	CHAT_SINGSTATE_NONE,
	CHAT_SINGSTATE_SINGED
} ChatSignState;

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
	CHAT_DSKESTATE_NONE,
	CHAT_DSKESTATE_AWAITING_KEYS,
	CHAT_DSKESTATE_FINISHED
} ChatDSKEState;

/* Chat auth type declaration */
typedef enum {
        CHAT_GKASTATE_NONE,
        CHAT_GKASTATE_AWAITING_UPFLOW,
        CHAT_GKASTATE_AWAITING_DOWNFLOW,
        CHAT_GKASTATE_FINISHED
} OtrlChatGKAState;

typedef struct {
        OtrlChatGKAState state;  /* the gka state */

        unsigned int position;      /* Our position in the participants order starting from the gka initiator */

        DH_keypair *keypair;		/* The keypair used for the gka */

        unsigned char participants_hash[CHAT_PARTICIPANTS_HASH_LENGTH];
} OtrlAuthGKAInfo;


typedef struct {
	ChatDSKEState state;

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
	CHAT_SHUTDOWNSTATE_NONE,
	CHAT_SHUTDOWNSTATE_AWAITING_ENDS,
	CHAT_SHUTDOWNSTATE_FINISHED
} ChatShutdownState;

typedef struct {
	int remaining;
	unsigned char *has_send_end;
	ChatShutdownState state;
} ShutdownInfo;

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

        OtrlList *pending_list; 			   /* The pending messages */

        ChatOfferInfo *offer_info;

        ChatAttestInfo *attest_info;

        OtrlChatEncInfo enc_info;          /* Info needed for encrypting messages */

        OtrlAuthGKAInfo gka_info;          /* Info needed for the GKA */

        OtrlAuthDSKEInfo *dske_info;	  	   /* Info needed for the DSKE */

        ShutdownInfo shutdown_info;

        OtrlMessageState msg_state;

        ChatSignState sign_state;

        SignKey *signing_key;		   /* The signing key */
        ChatIdKey *identity_key;
		unsigned char sid[CHAT_OFFER_SID_LENGTH];

        unsigned int protocol_version;     /* The version of OTR in use */

        /* Application data to be associated with this context */
        void *app_data;
        /* A function to free the above data when we forget this context */
        void (*app_data_free)(void *);
} OtrlChatContext;


typedef  struct ChatParticipantStruct {
        char *username; // This users username
        SignKey *sign_key; //This users signing key
        // TODO make sure the following is the fingerprint the participant is using and create another list with
        // fingerprints our user has marked as trusted for the participant
        ChatFingerprint *fingerprint;
        OtrlList *trusted_fingerprints;
        DAKE *dake;
	Shutdown *shutdown;

} ChatParticipant;

typedef enum {
	LEVEL_NONE,
	LEVEL_IN_PROGRESS,
	LEVEL_PRIVATE,
	LEVEL_FINISHED
} OtrlChatInfoPrivacyLevel;

typedef struct OtrlChatInfoStruct {
	char *accountname;
	char *protocol;
	otrl_chat_token_t chat_token;
	OtrlChatInfoPrivacyLevel level;
} OtrlChatInfo;

#endif /* CHAT_TYPES_H */
