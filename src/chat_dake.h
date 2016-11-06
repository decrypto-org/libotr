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

#ifndef CHAT_DAKE_H
#define CHAT_DAKE_H

#include <stddef.h>

#include "chat_id_key.h"
#include "dh.h"
#include "tdh.h"

//#include "chat_fingerprint.h"

#define DAKE_MAC_LEN 32 //TDH_MAC_LENGTH

enum {
	DAKE_NO_ERROR,
	DAKE_ERROR,
	DAKE_UNVERIFIED
};

typedef enum {
	DAKE_STATE_NONE,
	DAKE_STATE_WAITING_HANDSHAKE,
	DAKE_STATE_WAITING_CONFIRM,
	DAKE_STATE_WAITING_KEY,
	DAKE_STATE_DONE
} DAKEState;

typedef struct {
	TripleDH_handshake handshake;
	const unsigned char* fingerprint;
	DAKEState state;
} DAKE;

typedef struct {
	DH_keypair longterm;
	DH_keypair ephemeral;
} DAKEInfo;

typedef struct {
    gcry_mpi_t ephem_pub;
    gcry_mpi_t long_pub;
} DAKE_handshake_message_data;

typedef struct {
	unsigned char mac[TDH_MAC_LENGTH];
} DAKE_confirm_message_data;

typedef struct {
	unsigned char mac[TDH_MAC_LENGTH];
	unsigned char *key;
 	size_t keylen;
} DAKE_key_message_data;

//typedef struct {
//	char *key;
//	size_t keylen;
//	char mac[TDH_MAC_LENGTH];
//} DAKE_key_message_data;

void chat_dake_destroy(DAKE *dake);

void chat_dake_destroy_handshake_data(DAKE_handshake_message_data *data);

void chat_dake_destroy_confirm_data(DAKE_confirm_message_data *data);

void chat_dake_destroy_info(DAKEInfo *dake_info);

int chat_dake_init_keys(DAKEInfo *dake_info, ChatIdKeyPtr id_key,
                        const char* accountname, const char *protocol,
                        DAKE_handshake_message_data **dataToSend);


int chat_dake_init(DAKE *dake, DAKEInfo *dake_info);//, ChatFingerprint *fingerprint);

//int chat_dake_init(DAKE *dake, ChatIdKey *longterm,
//			DAKE_handshake_message_data **dataToSend);

int chat_dake_load_their_part(DAKE *dake, DAKE_handshake_message_data *data,
                               DAKE_confirm_message_data **dataToSend,
							   unsigned char** received_key_fingerprint);

/*int chat_dake_auth_encrypt(DAKE *dake, const char *msg,
                        size_t msglen, const char *ciphertext,
                        const char *mac);

int chat_dake_auth_decrypt(DAKE *dake, const char *ciphertext,
                           const char* cipherlen, char *msg,
                           const char *mac);
*/


int chat_dake_verify_confirm(DAKE *dake, unsigned char mac[TDH_MAC_LENGTH]);

int chat_dake_send_key(DAKE *dake, unsigned char* key_bytes, size_t keylen,
					   DAKE_key_message_data **dataToSend);

int chat_dake_receive_key(DAKE *dake, DAKE_key_message_data *data,
		 	  	  	  unsigned char **key, size_t *keylen);
#endif /* CHAT_DAKE_H */
