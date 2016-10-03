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

#include "chat_privkeydh.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <gcrypt.h>

#include "dh.h"
#include "privkey.h"
#include "chat_idkey.h"
#include "message.h"
#include "list.h"

static gcry_error_t chat_privkeydh_sexp_write(FILE *privf, gcry_sexp_t sexp)
{
    size_t buflen;
    char *buf;

    buflen = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    buf = malloc(buflen * sizeof *buf);
    if (buf == NULL && buflen > 0) {
	return gcry_error(GPG_ERR_ENOMEM);
    }
    gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buf, buflen);

    fprintf(privf, "%s", buf);
    free(buf);

    return gcry_error(GPG_ERR_NO_ERROR);
}


/* Read a sets of private DSA keys from a FILE* into the given
 * OtrlUserState.  The FILE* must be open for reading. */
gcry_error_t otrl_chat_privkeydh_read_FILEp(OtrlUserState us, FILE *privf)
{
    int privfd;
    struct stat st;
    char *buf;
    const char *token;
    size_t tokenlen;
    gcry_error_t err;
	gcry_sexp_t accounts; //Linguistic note. accounts means account sexp.
                          //Its not plural
    gcry_sexp_t allkeys;
    int i;
    OtrlListNode node;
    ChatIdKey *key;

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_read_FILEp: start\n");

    if (!privf) return gcry_error(GPG_ERR_NO_ERROR);

    /* Release any old ideas we had about our keys */
    otrl_list_clear(us->chat_privkey_list);

    /** Load the data into a buffer **/

    /* Get the file descriptor of the privkey file */
    privfd = fileno(privf);

    /* Use fstat to get the file size */
    if (fstat(privfd, &st)) {
    	err = gcry_error_from_errno(errno);
    	return err;
    }

    /* Allocate memory for a buffer to hold the file contents */
    buf = malloc(st.st_size * sizeof *buf);
    if (!buf && st.st_size > 0) {
    	return gcry_error(GPG_ERR_ENOMEM);
    }

    /* Read the file contents into the buffer */
    if (fread(buf, st.st_size, 1, privf) != 1) {
    	err = gcry_error_from_errno(errno);
    	free(buf);
    	return err;
    }

    /* Create an s-expression from the read buffer */
    err = gcry_sexp_new(&allkeys, buf, st.st_size, 0);
    free(buf);
    if (err) {
	    return err;
    }


    /* Validate that the s-expression is a "chat_privkeys" instance */
    token = gcry_sexp_nth_data(allkeys, 0, &tokenlen);
    if (tokenlen != 13 || strncmp(token, "chat_privkeys", 13)) {
	gcry_sexp_release(allkeys);
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }


    /* Iterate over each account in the list */
    for(i=1; i<gcry_sexp_length(allkeys); ++i) {

    	/* Get the ith "account" S-exp */
    	accounts = gcry_sexp_nth(allkeys, i);

        /* Parse the account sexpression */
    	key = chat_id_key_manager.parse(accounts);
    	if(!key) { goto error; }

        /* Append the parsed key in the privkey list */
    	node = otrl_list_append(us->chat_privkey_list, key);
        if(!node) { goto error_with_key; }

    	gcry_sexp_release(accounts);
	}
    gcry_sexp_release(allkeys);

    return gcry_error(GPG_ERR_NO_ERROR);

error_with_key:
    chat_id_key_manager.destroy_key(key);
error:
	otrl_list_clear(us->chat_privkey_list);
	gcry_sexp_release(accounts);
	gcry_sexp_release(allkeys);
	fprintf(stderr,"libotr-mpOTR: otrl_chat_privkeydh_read_FILEp: end error\n");
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
}

gcry_error_t chat_privkeydh_generate_start(OtrlUserState us, const char* accountname,
                                      const char* protocol, ChatIdKey **newkey)
{
	int err;
    ChatIdKey *key;

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_start: start\n");

    /* Generate a key */
    err = chat_id_key_manager.generate_key(&key);
    if(err || !key) { goto error; }

    //TODO maybe move the accountname and protocol copying in chat_idkey
    /* Copy the username in the key struct */
    key->accountname = strdup(accountname);
    if(!key->accountname) { goto error_with_key; }

    /* And the protocol */
    key->protocol = strdup(protocol);
    if(!key->protocol) { goto error_with_accountname; }

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_start: end\n");

    *newkey = key;
    return gcry_error(GPG_ERR_NO_ERROR);

error_with_accountname:
	fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_start: error_with_accountname\n");
    free((key)->accountname);
error_with_key:
	fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_start: error_with_key\n");
    chat_id_key_manager.destroy_key(key);
error:
	fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_start: error\n");
    return 1;
}

gcry_error_t chat_privkeydh_account_write(FILE *privf, ChatIdKey *k)
{
    gcry_error_t err;
    gcry_sexp_t keys;


    /* Serialize the key to be written */
    err = chat_id_key_manager.serialize(k, &keys);
    if(err) { goto error; }

    /* Write the sexpression in the file */
    chat_privkeydh_sexp_write(privf, keys);

    gcry_sexp_release(keys);

    return gcry_error(GPG_ERR_NO_ERROR);

error:
    return err;
}

gcry_error_t chat_privkeydh_generate_finish(OtrlUserState us, ChatIdKey *newkey, FILE *privf)
{
	OtrlListIterator iter;
    OtrlListNode cur, node;
    ChatIdKey *k;
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_finish: start\n");

    if(!newkey || !us || !privf) { goto error; }

	/* Print the starting parenthesis of the s expression along with its
	name */
	fprintf(privf, "(chat_privkeys\n");

	/* We iterate over every key in the privkey list */
	iter = otrl_list_iterator_new(us->chat_privkey_list);
	if(!iter) { goto error; }
	while(otrl_list_iterator_has_next(iter)) {
		cur = otrl_list_iterator_next(iter);
		k = otrl_list_node_get_payload(cur);

		/* If the current element is for the same account as the newley
		 created key then pass on to the next list element. This means
		 that if there is an older key in the list for the same account
		 we will forget about it, and write only the new key */
		if(!strcmp(k->accountname, newkey->accountname) &&
		   !strcmp(k->protocol, newkey->protocol)) {

			/* Remove the old key from the list */
			otrl_list_remove_and_free(us->chat_privkey_list, cur);
		}
		else {
			// TODO Dimitris error handling
			/* If this is not an old key write it in the key file */
			chat_privkeydh_account_write(privf, k);
		}
	}

	/* Write the new key in the file */
	// TODO Dimitris error handling
	chat_privkeydh_account_write(privf,newkey);
	fprintf(privf, ")\n");

	//TODO maybe append instead of inserting to be more efficient? This will break the find call on the list though
	/* If the append is not successfull then destroy the key and return error */
	node = otrl_list_insert(us->chat_privkey_list, newkey);
	if(!node){ goto error_with_iter; }

	otrl_list_iterator_free(iter);

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_finish: end\n");
    return err;

error_with_iter:
    otrl_list_iterator_free(iter);
error:
    return 1;
}

int otrl_chat_privkeydh_generate_FILEp(OtrlUserState us, FILE *privf,
                                       const char *accountname,
                                       const char *protocol)
{
    ChatIdKey *newkey = NULL;
    gcry_error_t err;

    fprintf(stderr,"libotr-mpOTR: otrl_chat_privkeydh_generate_FILEp: start\n");

    if(!accountname || !protocol)
    	return 1;

    /* Start the generation of a new key */
    err = chat_privkeydh_generate_start(us, accountname, protocol, &newkey);

    if(newkey) {
        /* If it was succesfully generated then finalize the generation */
        err = chat_privkeydh_generate_finish(us, newkey, privf);
        if(err) {
        	fprintf(stderr,"libotr-mpOTR: otrl_chat_privkeydh_generate_FILEp: error\n");
            chat_id_key_manager.destroy_key(newkey);
        }
    }
    fprintf(stderr,"libotr-mpOTR: otrl_chat_privkeydh_generate_FILEp: end\n");

    return err;
}
ChatIdKey * chat_privkeydh_find_or_generate(OtrlUserState us, const OtrlMessageAppOps *ops, const char *accountname, const char* protocol)
{
	ChatIdKey *key;
	int keyexists;

	fprintf(stderr, "libotr-mpOTR: chat_privkeydh_find_or_generate: start\n");

    /* Check if the requested key in the user state */
    keyexists = chat_privkeydh_key_exists(us, accountname, protocol);

    /* If it does not, create it now */
	if(!keyexists) {
		ops->chat_privkey_create(NULL, accountname, protocol);
	}

    /* Now look for the key in the list. It must be in there */
	key = chat_id_key_manager.find_key(us->chat_privkey_list, accountname, protocol);
    if(!key) {
        return NULL;
    }

	fprintf(stderr, "libotr-mpOTR: chat_privkeydh_find_or_generate: end\n");

	return key;
}

int chat_privkeydh_key_exists(OtrlUserState us, const char *accountname, const char *protocol)
{
	OtrlListIterator iter;
	OtrlListNode cur;
	ChatIdKey *k;
	int res = 0;

    /* Iterate over every key in the privkey list */
	iter = otrl_list_iterator_new(us->chat_privkey_list);
	while(!res && otrl_list_iterator_has_next(iter)) {
		cur = otrl_list_iterator_next(iter);
		k = otrl_list_node_get_payload(cur);

        /* Check if we are on the requested key, and if yes return TRUE */
		if(strcmp(k->accountname, accountname) == 0 && strcmp(k->protocol, protocol) == 0 ) {
			res = 1;
		}
	}

	otrl_list_iterator_free(iter);

	return res;
}

//TODO this function should probably accept a SignKey parameter isntead of
//a gcry_mpi_t
unsigned char *chat_privkeydh_get_fingerprint(gcry_mpi_t pubkey)
{
	gcry_error_t err;
	gcry_md_hd_t md;
	unsigned char *buf, *hash;
	size_t buflen;

    /* Get the pubkey length*/
	gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&buflen,pubkey);

    /* Allocate memory for a temporary buffer to hold the pubkey data */
	buf = malloc(buflen * sizeof *buf);
	if(!buf) { goto error; }

    /* Print the pubkey in the buf */
	gcry_mpi_print(GCRYMPI_FMT_HEX,buf,buflen,NULL,pubkey);

    /* Open a digest */
	err = gcry_md_open(&md, GCRY_MD_SHA256, 0);
	if(err){ goto error_with_buf; }

    /* And write the data contained in buf to the digest */
	gcry_md_write(md, buf, buflen);

    /* Allocate memory for the hash result */
	hash = malloc(CHAT_FINGERPRINT_SIZE * sizeof *hash);
	if(!hash) { goto error_with_buf; }

    /* And finally copy the result from the digest */
	memcpy(hash, gcry_md_read(md, GCRY_MD_SHA256), CHAT_FINGERPRINT_SIZE);
	gcry_md_close(md);

    free(buf);

	return hash;

error_with_buf:
	free(buf);
error:
	return NULL;
}
