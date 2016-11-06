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

#include "chat_dake.h"
#include "chat_types.h"
#include "chat_privkeydh.h"
#include "tdh.h"
#include "list.h"

#define CONF_MSG "key confirmation msg"
#define CONF_MSG_LEN 20

void chat_dake_destroy(DAKE *dake)
{
	tdh_handshake_destroy(&dake->handshake);
}

void chat_dake_destroy_info(DAKEInfo *dake_info)
{
    //otrl_dh_keypair_free(&dake_info->longterm);
    otrl_dh_keypair_free(&dake_info->ephemeral);
}

int chat_dake_auth_encrypt(DAKE *dake,
                           unsigned char *msg, size_t msglen,
                           unsigned char *assoc_data, size_t assoc_datalen,
						   unsigned char *ciphertext, unsigned char *mac)
{
	fprintf(stderr,"libotr-mpOTR: chat_dake_auth_encrypt: start\n");
    if(tdh_handshake_encrypt(&dake->handshake, ciphertext, msglen, msg, msglen))
        return 1;

    //fprintf(stderr,"libotr-mpOTR: chat_dake_auth_encrypt: after encrypt\n");

    if(tdh_handshake_mac(&dake->handshake, mac, ciphertext, msglen, assoc_data, assoc_datalen))
        return 1;

	fprintf(stderr,"libotr-mpOTR: chat_dake_auth_encrypt: end\n");
    return 0;
}

int chat_dake_auth_decrypt(DAKE *dake, unsigned char *ciphertext,
                           size_t cipherlen, unsigned char *assoc_data,
                           size_t assoc_datalen, unsigned char *msg, unsigned char *mac)
{
	fprintf(stderr,"chat_dake_auth_decrypt: start\n");
    if(tdh_handshake_mac_verify(&dake->handshake, mac, ciphertext, cipherlen, assoc_data,
                                assoc_datalen))
        return 1;

    //fprintf(stderr,"libotr-mpOTR: chat_dake_auth_decrypt: after verify\n");

    if(tdh_handshake_decrypt(&dake->handshake, msg, cipherlen, ciphertext, cipherlen))
        return 1;

    fprintf(stderr,"chat_dake_auth_decrypt: end\n");
    return 0;
}

void chat_dake_destroy_handshake_data(DAKE_handshake_message_data *data)
{
	gcry_mpi_release(data->ephem_pub);
	gcry_mpi_release(data->long_pub);
}

int chat_dake_init_keys(DAKEInfo *dake_info, ChatIdKey *key,
                        const char* accountname, const char *protocol,
                        DAKE_handshake_message_data **dataToSend)
{
	int err;

	fprintf(stderr,"libotr-mpOTR: chat_dake_init_keys: start\n");
    *dataToSend = malloc(sizeof(**dataToSend));
    if(!*dataToSend) {
        return DAKE_ERROR;
    }

	//fprintf(stderr,"libotr-mpOTR: chat_dake_init_keys: after alloc\n");
    //key = chat_idkey_find(longterm_key_list, accountname, protocol);
    if(!key) {
        free(*dataToSend);
        return DAKE_ERROR;
    }
    dake_info->longterm = key->keyp;

	//fprintf(stderr,"libotr-mpOTR: chat_dake_init_keys: after key check\n");

    err = tdh_handshake_gen_ephemeral(&dake_info->ephemeral);
    if(err) {
        free(*dataToSend);
        return DAKE_ERROR;
    }

	//fprintf(stderr,"libotr-mpOTR: chat_dake_init_keys: after ephemeral key generation\n");

    (*dataToSend)->long_pub = gcry_mpi_copy(dake_info->longterm.pub);
    (*dataToSend)->ephem_pub = gcry_mpi_copy(dake_info->ephemeral.pub);

	//fprintf(stderr,"libotr-mpOTR: chat_dake_init_keys: start\n");

    fprintf(stderr,"chat_dake_init_keys: end\n");
    return DAKE_NO_ERROR;
}

int chat_dake_init(DAKE *dake, DAKEInfo *dake_info)//, ChatFingerprint *fingerprint)
{

	fprintf(stderr,"chat_dake_init: start\n");

    tdh_handshake_init(&dake->handshake);
    tdh_handshake_load_longterm(&dake->handshake, &dake_info->longterm);
    tdh_handshake_load_ephemeral(&dake->handshake, &dake_info->ephemeral);
    dake->state = DAKE_STATE_WAITING_HANDSHAKE;
    //dake->fingerprint = fingerprint ? fingerprint->fingerprint : NULL;
    fprintf(stderr,"chat_dake_init: end\n");
    return DAKE_NO_ERROR;
}

void chat_dake_destroy_confirm_data(DAKE_confirm_message_data *data)
{

}


int chat_dake_load_their_part(DAKE *dake,
                               DAKE_handshake_message_data *data,
                               DAKE_confirm_message_data **dataToSend,
							   unsigned char** received_key_fingerprint)
{
    gcry_mpi_t long_pub = data->long_pub;
    gcry_mpi_t ephem_pub = data->ephem_pub;
    unsigned char *fingerprint;
 //   char *hexed_fingerprint;

	fprintf(stderr,"chat_dake_load_their_part: start\n");

    if(tdh_handshake_load_their_pub(&dake->handshake, long_pub, ephem_pub))
        return DAKE_ERROR;

    if(tdh_handshake_compute_keys(&dake->handshake))
        return DAKE_ERROR;

    *dataToSend = malloc(sizeof(**dataToSend));
    if(!dataToSend){
        return DAKE_ERROR;
    }

    if(chat_dake_auth_encrypt(dake, NULL, 0, (unsigned char *) CONF_MSG, CONF_MSG_LEN,
                              NULL, (*dataToSend)->mac)) {
        free(*dataToSend);
        return DAKE_ERROR;
    }

    dake->state = DAKE_STATE_WAITING_CONFIRM;


    fingerprint = chat_privkeydh_get_fingerprint(data->long_pub);
//    if(!dake->fingerprint) {
//    	fprintf(stderr,"chat_dake_load_their_part: end unverified\n");
//		hexed_fingerprint = chat_fingerprint_bytes_to_hex(fingerprint);
//		fprintf(stderr,"libotr-mpOTR: chat_dake_load_their_part: Key with fingerprint %s is not verified\n", hexed_fingerprint);
//		free(hexed_fingerprint);
//    	return DAKE_UNVERIFIED;
//    }
//    else {
//   	if(memcmp(dake->fingerprint, fingerprint, CHAT_FINGERPRINT_SIZE)) {
//    		hexed_fingerprint = chat_fingerprint_bytes_to_hex(fingerprint);
//    		fprintf(stderr,"libotr-mpOTR: chat_dake_load_their_part: Key with fingerprint %s did not match\n", hexed_fingerprint);
//    		free(hexed_fingerprint);
//    		return DAKE_ERROR;
//    	}
//    }
//    free(fingerprint);
    *received_key_fingerprint = fingerprint;
    fprintf(stderr,"chat_dake_load_their_part: end\n");
    return DAKE_NO_ERROR;
}

int chat_dake_verify_confirm(DAKE *dake, unsigned char mac[TDH_MAC_LENGTH])
{
    return chat_dake_auth_decrypt(dake, NULL, 0, (unsigned char *) CONF_MSG, CONF_MSG_LEN, NULL, mac);
}

int chat_dake_send_key(DAKE *dake, unsigned char* key_bytes, size_t keylen,
					   DAKE_key_message_data **dataToSend)
{

	fprintf(stderr,"chat_dake_send_key: start\n");

	*dataToSend = malloc(sizeof(**dataToSend));
	if(!*dataToSend) {
		return 1;
	}

	//fprintf(stderr,"chat_dake_send_key: after data malloc, keylen: %lu\n", keylen);

	(*dataToSend)->key = malloc(keylen * sizeof(*(*dataToSend)->key));
	if(!(*dataToSend)->key) {
		free(*dataToSend);
		return 1;
	}

	//fprintf(stderr,"chat_dake_send_key: after data  key malloc\n");

	(*dataToSend)->keylen = keylen;

	if(!dake)
		fprintf(stderr,"chat_dake_send_key: dake is null\n");

	if(chat_dake_auth_encrypt(dake, key_bytes, keylen, NULL, 0, (*dataToSend)->key, (*dataToSend)->mac)) {
		free((*dataToSend)->key);
		free(*dataToSend);
		return 1;
	}

	//fprintf(stderr,"chat_dake_send_key: after data  auth encrypt\n");

	dake->state = DAKE_STATE_WAITING_KEY;
	fprintf(stderr,"chat_dake_send_key: end\n");
	return 0;
}

int chat_dake_receive_key(DAKE *dake, DAKE_key_message_data *data,
		 	  	  	  unsigned char **key, size_t *keylen)
{
	fprintf(stderr,"chat_dake_receive_key: start\n");

	*key = malloc(data->keylen);
	if(!*key) {
		return 1;
	}

	if(chat_dake_auth_decrypt(dake, data->key, data->keylen, NULL, 0, *key,
			                  data->mac)) {
		free(*key);
		return 1;
	}

	*keylen = data->keylen;

	fprintf(stderr,"chat_dake_receive_key: end\n");
	return 0;
}
