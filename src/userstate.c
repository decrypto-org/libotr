/*
 *  Off-the-Record Messaging library
 *  Copyright (C) 2004-2012  Ian Goldberg, Rob Smits, Chris Alexander,
 *  			      Willy Lew, Lisa Du, Nikita Borisov
 *                           <otr@cypherpunks.ca>
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

/* system headers */
#include <stdlib.h>

/* libotr headers */
#include "context.h"
#include "privkey.h"
#include "userstate.h"
#include "chat_context.h" 		/* DIKOMAS */
#include "list.h" 				/* DIKOMAS */
#include "chat_idkey.h" 		/* DIKOMAS */
#include "chat_fingerprint.h" 	/* DIKOMAS */

/* Create a new OtrlUserState.  Most clients will only need one of
 * these.  A OtrlUserState encapsulates the list of known fingerprints
 * and the list of private keys; if you have separate files for these
 * things for (say) different users, use different OtrlUserStates.  If
 * you've got only one user, with multiple accounts all stored together
 * in the same fingerprint store and privkey store files, use just one
 * OtrlUserState. */
OtrlUserState otrl_userstate_create(void)
{
    OtrlUserState us = malloc(sizeof(struct s_OtrlUserState));
    if (!us) return NULL;
    us->context_root = NULL;

    /* DIKOMAS */
    us->chat_context_list = otrl_list_create(&chat_context_listOps, sizeof(OtrlChatContext));
    if(!us->chat_context_list) { goto error; }

    us->chat_privkey_list = otrl_list_create(&chat_idkey_listOps, sizeof(ChatIdKey));
    if(!us->chat_privkey_list) { goto error_with_chat_context_list; }

    us->chat_fingerprints = otrl_list_create(&chat_fingerprint_listOps, sizeof(OtrlChatFingerprint));
    if(!us->chat_fingerprints) { goto error_with_chat_privkey_list; }
    /* ******* */

    us->privkey_root = NULL;
    us->instag_root = NULL;
    us->pending_root = NULL;
    us->timer_running = 0;
    return us;

/* DIKOMAS */
error_with_chat_privkey_list:
	otrl_list_free(us->chat_privkey_list);
error_with_chat_context_list:
	otrl_list_free(us->chat_context_list);
error:
	return NULL;
/* ******* */
}

/* Free a OtrlUserState.  If you have a timer running for this userstate,
stop it before freeing the userstate. */
void otrl_userstate_free(OtrlUserState us)
{
    otrl_context_forget_all(us);

    /* DIKOMAS */
    otrl_list_free(us->chat_context_list);
    otrl_list_free(us->chat_privkey_list);
    otrl_list_free(us->chat_fingerprints);
    /* ******* */

    otrl_privkey_forget_all(us);
    otrl_privkey_pending_forget_all(us);
    otrl_instag_forget_all(us);
    free(us);
}
