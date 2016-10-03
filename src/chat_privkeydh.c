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

static gcry_error_t chat_privkeydh_sexp_write(FILE *privf, gcry_sexp_t sexp)
{
    size_t buflen;
    char *buf;

    buflen = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    buf = malloc(buflen);
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
	gcry_sexp_t accounts;
    gcry_sexp_t allkeys;
    int i;
    OtrlListNode *node;
    ChatIdKey *key;

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_read_FILEp: start\n");

    if (!privf) return gcry_error(GPG_ERR_NO_ERROR);

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_read_FILEp: before clear\n");
    /* Release any old ideas we had about our keys */
    otrl_list_clear(us->chat_privkey_list);

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_read_FILEp: before load\n");
    /* Load the data into a buffer */
    privfd = fileno(privf);
    if (fstat(privfd, &st)) {
    	err = gcry_error_from_errno(errno);
    	return err;
    }
    buf = malloc(st.st_size);
    if (!buf && st.st_size > 0) {
    	return gcry_error(GPG_ERR_ENOMEM);
    }
    if (fread(buf, st.st_size, 1, privf) != 1) {
    	err = gcry_error_from_errno(errno);
    	free(buf);
    	return err;
    }

    err = gcry_sexp_new(&allkeys, buf, st.st_size, 0);
    free(buf);
    if (err) {
	    return err;
    }
    fprintf(stderr,"libotr-mpOTR: otrl_chat_privkeydh_read_FILEp: before nth_data \n");
    token = gcry_sexp_nth_data(allkeys, 0, &tokenlen);
    if (tokenlen != 13 || strncmp(token, "chat_privkeys", 13)) {
	gcry_sexp_release(allkeys);
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }

    fprintf(stderr,"libotr-mpOTR: otrl_chat_privkeydh_read_FILEp: before for\n");
    /* Get each account */
    for(i=1; i<gcry_sexp_length(allkeys); ++i) {

    	/* Get the ith "account" S-exp */
    	accounts = gcry_sexp_nth(allkeys, i);

    	/* It's really an "account" S-exp? */
    	/*token = gcry_sexp_nth_data(accounts, 0, &tokenlen);
    	if (tokenlen != 7 || strncmp(token, "account", 7)) {
    		gcry_sexp_release(accounts);
    		gcry_sexp_release(allkeys);
    		return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    	}
    	*/
    	key = chat_id_key_manager.parse(accounts);
    	if(!key) goto error;

    	node = otrl_list_append(us->chat_privkey_list, key);
        if(!node) {goto error_with_key; }

    	gcry_sexp_release(accounts);
	}
    gcry_sexp_release(allkeys);

    fprintf(stderr,"libotr-mpOTR: otrl_chat_privkeydh_read_FILEp: end\n");
    otrl_list_dump(us->chat_privkey_list);
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
    gcry_error_t err;
    ChatIdKey *key;

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_start: start\n");

    err = chat_id_key_manager.generate_key(&key);
    if(err || !key) { goto error; }

    key->accountname = strdup(accountname);
    if(!key->accountname) { goto error_with_key; }

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

  //  fprintf(privf, " (account");

    err = chat_id_key_manager.serialize(k, &keys);
    if(!err) {
        chat_privkeydh_sexp_write(privf, keys);
        gcry_sexp_release(keys);
    }

    //fprintf(privf, ")\n");

    return err;

}

gcry_error_t chat_privkeydh_generate_finish(OtrlUserState us, ChatIdKey *newkey, FILE *privf)
{
    OtrlListNode *cur;
    OtrlListNode *node = NULL;
    ChatIdKey *k;
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_finish: start\n");
    if(newkey && us && privf) {
    	fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_finish: in if\n");
        fprintf(privf, "(chat_privkeys\n");

        fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_finish: before for\n");
        for(cur = us->chat_privkey_list->head; cur!=NULL; cur=cur->next) {
            k = cur->payload;

            if(!strcmp(k->accountname, newkey->accountname) &&
               !strcmp(k->protocol, newkey->protocol)) {
                continue;
            }

            chat_privkeydh_account_write(privf, k);
        }
        fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_finish: after for\n");

        chat_privkeydh_account_write(privf,newkey);
        fprintf(privf, ")\n");

        //fseek(privf, 0, SEEK_SET);
        fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_finish: before append\n");

        //TODO maybe append instead of inserting to be more efficient? This will break the find call on the list though
        /* If the append is not successfull then destroy the key and return error */
        node = otrl_list_insert(us->chat_privkey_list, newkey);
        if(!node){ goto append_failed; }


    }
    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_finish: end\n");
    return err;

append_failed:
    chat_id_key_manager.destroy_key(newkey);
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
    err = chat_privkeydh_generate_start(us, accountname, protocol, &newkey);

    if(newkey) {
        err = chat_privkeydh_generate_finish(us, newkey, privf);
        if(err) {
        	fprintf(stderr,"libotr-mpOTR: otrl_chat_privkeydh_generate_FILEp: error\n");
            chat_id_key_manager.destroy_key(newkey);
        }
    }
    fprintf(stderr,"libotr-mpOTR: otrl_chat_privkeydh_generate_FILEp: end\n");

    return err;
}
ChatIdKey * chat_privkeydh_find_or_generate(OtrlUserState us, const OtrlMessageAppOps *ops, const char *accountname, const char* protocol){
	ChatIdKey *key;

	int keyexists = chat_privkeydh_key_exists(us, accountname, protocol);
	if(!keyexists) {
		ops->chat_privkey_create(NULL, accountname, protocol);
	}

	fprintf(stderr, "chat_privkeydh_find_or_generate: dumping key list\n");
	otrl_list_dump(us->chat_privkey_list);

	key = chat_id_key_manager.find_key(us->chat_privkey_list, accountname, protocol);

	fprintf(stderr, "chat_privkeydh_find_or_generate: after find_key\n");

	return key;
}

int chat_privkeydh_key_exists(OtrlUserState us, const char *accountname, const char *protocol)
{
	OtrlListNode *cur;
	ChatIdKey *k;

	for(cur = us->chat_privkey_list->head; cur != NULL; cur = cur->next) {
		k = cur->payload;
		if(strcmp(k->accountname, accountname) == 0 && strcmp(k->protocol, protocol) == 0 ) {
			return 1;
		}
	}

	return 0;
}

unsigned char *chat_privkeydh_get_fingerprint(gcry_mpi_t pubkey)
{
	gcry_error_t err;
	gcry_md_hd_t md;
	unsigned char *buf, *hash;
	size_t buflen;

	gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&buflen,pubkey);
	buf = malloc(buflen * sizeof *buf);
	if(!buf) { goto error; }

	gcry_mpi_print(GCRYMPI_FMT_HEX,buf,buflen,NULL,pubkey);

	err = gcry_md_open(&md, GCRY_MD_SHA256, 0);
	if(err){ goto error_with_buf; }

	gcry_md_write(md, buf, buflen);

	hash = malloc(CHAT_FINGERPRINT_SIZE * sizeof *hash);
	if(!hash) { goto error_with_buf; }

	memcpy(hash, gcry_md_read(md, GCRY_MD_SHA256), CHAT_FINGERPRINT_SIZE);
	gcry_md_close(md);

    free(buf);

	return hash;

error_with_buf:
	free(buf);
error:
	return NULL;
}
