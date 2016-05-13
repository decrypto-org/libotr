#include "chat_privkeydh.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <gcrypt.h>

#include "dh.h"
#include "privkey.h"
#include "chat_idkey.h"

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
    	ChatIdKey *key;

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
    	if(!key) goto err;
    	otrl_list_append(us->chat_privkey_list, key);
    	gcry_sexp_release(accounts);
	}
    gcry_sexp_release(allkeys);

    fprintf(stderr,"libotr-mpOTR: otrl_chat_privkeydh_read_FILEp: end\n");
    otrl_list_dump(us->chat_privkey_list);
    return gcry_error(GPG_ERR_NO_ERROR);

err:
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

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_start: start\n");
    err = chat_id_key_manager.generate_key(newkey);
    if(err || !*newkey)
        return 1;

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_start: before strdup\n");
    (*newkey)->accountname = strdup(accountname);
    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_start: before second strdup\n");
    (*newkey)->protocol = strdup(protocol);

    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_start: end\n");
    return gcry_error(GPG_ERR_NO_ERROR);

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
        //TODO add code to check if append succeded
        otrl_list_append(us->chat_privkey_list, newkey);

    }
    fprintf(stderr,"libotr-mpOTR: otrl_privkeydh_generate_finish: end\n");
    return err;
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
