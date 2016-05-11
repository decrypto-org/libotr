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

#include "proto.h"
#include "tlv.h"
#include "dh.h"
#include "instag.h"

#include <gcrypt.h>

/* Chat Message type declerations */

typedef enum {
	OTRL_MSGTYPE_CHAT_NOTOTR,
    OTRL_MSGTYPE_CHAT_UPFLOW,
    OTRL_MSGTYPE_CHAT_DOWNFLOW,
    OTRL_MSGTYPE_CHAT_DATA
} OtrlChatMessageType;

typedef void * MessagePayloadPtr;

typedef struct OtrlChatMessageStruct {
		int16_t protoVersion;
		OtrlChatMessageType msgType;
		otrl_instag_t senderInsTag;
		otrl_instag_t chatInsTag;
		MessagePayloadPtr payload;
		void (*payload_free)(MessagePayloadPtr);
		unsigned char * (*payload_serialize)(MessagePayloadPtr, size_t *);
} OtrlChatMessage;

//TODO Remove this struct. it is not used
typedef struct OtrlChatMessagePayloadQueryStruct {
        //TODO this is to change
        unsigned char key[32];
} OtrlChatMessagePayloadQuery;

//TODO Remove this struct. it is not used
typedef struct OtrlChatMessagePayloadQueryAckStruct {
        //TODO this is to change
        unsigned char magicnum[4];
} OtrlChatMessagePayloadQueryAck;

typedef struct OtrlChatMessagePayloadUpflowStruct {
		unsigned int recipient;
		unsigned char partlistHash[CHAT_PARTICIPANTS_HASH_LENGTH];
		OtrlList *interKeys;
} OtrlChatMessagePayloadGkaUpflow;

typedef struct OtrlChatMessagePayloadDownflowStruct {
		unsigned char partlistHash[CHAT_PARTICIPANTS_HASH_LENGTH];
		OtrlList *interKeys;
} OtrlChatMessagePayloadGkaDownflow;

typedef struct OtrlChatMessagePayloadDataStruct {
        unsigned char ctr[8];
        size_t datalen;
        unsigned char *ciphertext;
} OtrlChatMessagePayloadData;


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


/* Chat auth type declaration */
typedef enum {
        OTRL_CHAT_GKASTATE_NONE,
        OTRL_CHAT_GKASTATE_AWAITING_DOWNFLOW,
        OTRL_CHAT_GKASTATE_FINISHED
} OtrlChatAuthGKAState;

typedef struct {
        OtrlChatAuthGKAState state;  /* the gka state */

        unsigned int position;      /* Our position in the participants order starting from the gka initiator */

        DH_keypair *keypair;		/* The keypair used for the gka */

        unsigned char participants_hash[CHAT_PARTICIPANTS_HASH_LENGTH];
} OtrlAuthGKAInfo;



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

        Fingerprint fingerprint_root;      /* The root of a linked list of
                                              Fingerprints entries. This list will
                                              only be populated in master contexts.
                                              For child contexts,
                                              fingerprint_root.next will always
                                              point to NULL. */

        OtrlChatEncInfo enc_info;              /* Info needed for encrypting messages */

        OtrlAuthGKAInfo gka_info;          /* Info needed for the GKA */

        OtrlMessageState msg_state;

        Fingerprint *active_fingerprint;   /* Which fingerprint is in use now?
                                              A pointer into the above list */

        unsigned char sessionid[20];       /* The sessionid and bold half */
        size_t sessionid_len;              /* determined when this private */
        OtrlSessionIdHalf sessionid_half;  /* connection was established. */

        unsigned int protocol_version;     /* The version of OTR in use */

        /* Application data to be associated with this context */
        void *app_data;
        /* A function to free the above data when we forget this context */
        void (*app_data_free)(void *);
} OtrlChatContext;


typedef  struct OtrlChatParticipantStruct {
        char *username; // This users username

        gcry_mpi_t signing_pub_key; //This users signing key

} OtrlChatParticipant;

#endif /* CHAT_TYPES_H */
