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

#include <stdio.h>
#include <stdlib.h>

#include "chat_id_key.h"
#include "chat_dh_key.h"

#define CONF_MSG "key confirmation msg"
#define CONF_MSG_LEN 20

//TODO refactor error handling KOSTIS
//TODO add comments

void chat_dake_destroy(DAKE *dake)
{
	tdh_handshake_destroy(&dake->handshake);
}

void chat_dake_destroy_info(DAKEInfo *dake_info)
{
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

int chat_dake_init_keys(DAKEInfo *dake_info, ChatIdKeyPtr id_key,
                        const char* accountname, const char *protocol,
                        DAKE_handshake_message_data **dataToSend)
{
	int err;
	ChatDHKeyPtr dh_key = NULL;

    *dataToSend = malloc(sizeof(**dataToSend));
    if(!*dataToSend) {
        return DAKE_ERROR;
    }

    if(!id_key) {
        free(*dataToSend);
        return DAKE_ERROR;
    }

    dh_key = chat_id_key_get_internal_key(id_key);

    //dake_info->longterm = key->keyp;
    dake_info->longterm = chat_dh_key_get_keypair(dh_key);

    err = tdh_handshake_gen_ephemeral(&dake_info->ephemeral);
    if(err) {
        free(*dataToSend);
        return DAKE_ERROR;
    }

    (*dataToSend)->long_pub = gcry_mpi_copy(dake_info->longterm.pub);
    (*dataToSend)->ephem_pub = gcry_mpi_copy(dake_info->ephemeral.pub);

    return DAKE_NO_ERROR;
}

int chat_dake_init(DAKE *dake, DAKEInfo *dake_info)
{

	fprintf(stderr,"chat_dake_init: start\n");

    tdh_handshake_init(&dake->handshake);
    tdh_handshake_load_longterm(&dake->handshake, &dake_info->longterm);
    tdh_handshake_load_ephemeral(&dake->handshake, &dake_info->ephemeral);
    dake->state = DAKE_STATE_WAITING_HANDSHAKE;

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


    //fingerprint = chat_privkeydh_get_fingerprint(data->long_pub);
    fingerprint = chat_dh_key_pub_fingerprint_create(data->long_pub);
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
	if(!*dataToSend) { goto error; }

	(*dataToSend)->key = malloc(keylen * sizeof(*(*dataToSend)->key));
	if(!(*dataToSend)->key) { goto error_with_data; }

	(*dataToSend)->keylen = keylen;

	if(!dake) {
		fprintf(stderr,"chat_dake_send_key: dake is null\n");
        goto error_with_key;
    }

	if(chat_dake_auth_encrypt(dake, key_bytes, keylen, NULL, 0, (*dataToSend)->key, (*dataToSend)->mac)) {
        goto error_with_key;
	}

	dake->state = DAKE_STATE_WAITING_KEY;
	fprintf(stderr,"chat_dake_send_key: end\n");
	return 0;

error_with_key:
    free((*dataToSend)->key);
error_with_data:
    free(*dataToSend);
    dataToSend = NULL;
error:
    return 1;
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
