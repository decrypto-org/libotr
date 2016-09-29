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

#ifndef CHAT_PARTICIPANT_H
#define CHAT_PARTICIPANT_H

#define MESSAGES_HASH_LEN 64

#include "chat_dake.h"
#include "chat_fingerprint.h"
#include "chat_sign.h"
#include "list.h"

typedef enum {
	SHUTDOWN_WAITING_END,
	SHUTDOWN_FINISHED
} ChatParticipantShutdownState;

typedef struct {
	ChatParticipantShutdownState state;
} ChatParticipantShutdown;

typedef struct ChatParticipant * ChatParticipantPtr;

/* TODO docstring */
size_t chat_participant_size();

/* TODO docstring */
char * chat_participant_get_username(ChatParticipantPtr participant);

/* TODO docstring */
SignKey * chat_participant_get_sign_key(ChatParticipantPtr participant);

/* TODO docstring */
void chat_participant_set_sign_key(ChatParticipantPtr participant, SignKey *sign_key);

/* TODO docstring */
OtrlChatFingerprintPtr chat_participant_get_fingerprint(ChatParticipantPtr participant);

/* TODO docstring */
void chat_participant_set_fingerprint(ChatParticipantPtr participant, OtrlChatFingerprintPtr fingerprint);

/* TODO docstring */
OtrlListPtr chat_participant_get_fingerprints(ChatParticipantPtr participant);

/* TODO docstring */
DAKE * chat_participant_get_dake(ChatParticipantPtr participant);

/* TODO docstring */
void chat_participant_set_dake(ChatParticipantPtr participant, DAKE *dake);

/* TODO docstring */
OtrlListPtr chat_participant_get_messages(ChatParticipantPtr participant);

/* TODO docstring */
unsigned char * chat_participant_get_messages_hash(ChatParticipantPtr participant);

/* TODO docstring */
int chat_participant_get_consensus(ChatParticipantPtr participant);

/* TODO docstring */
void chat_participant_set_consensus(ChatParticipantPtr participant, int consesnus);

/**
  Free a pariticpant

  This function frees the participant a, and any data
  within the participant

  @param participant The participant to be free'd

  @return void
 */
void chat_participant_free(ChatParticipantPtr participant);

/**
  Find a participant in the ctx context's participants list

  This function searches the participants list in ctx to find the user with the specifed
  user name

  @param participants_list  The list where the user will be searched
  @param username 			The user name of the user to be searced
  @param position 			If the user is found the position contains his position in the list

  @return If the user is found a pointer to it will be returned. Otherwise NULL
 */
ChatParticipantPtr chat_participant_find(OtrlListPtr participants_list, const char *username, unsigned int *position);

/**
  Add a user to the ctx's participants list

  This function will add a new user defined in participant in the ctx's participants list

  @param participants_list 	The list where we will add the user
  @param participan 		The user to be added

  @return 1 if the user was sucessfully added. 0 otherwise.
 */
int chat_participant_add(OtrlListPtr participants_list, const ChatParticipantPtr participant);

/**
 Add a group of usernames in a list

 This function takes a participant list and adds usernames_size usernames contained in usernames

 @param participants_list The list where the participants will be added
 @param usernames An array of null termintated user names
 @param usernames_size the lenght of the usernames array

 @return 0 if there was no error. 1 otherwise
 */
int chat_participant_list_from_usernames(OtrlListPtr participants_list, char **usernames, unsigned int usernames_size);


/**
 Get the position of an accountname in a list

 @param participants The list of the participants
 @param accountname The account name we are searching for
 @param position If found, contains the position of the participant in the list

 @return 0 if found. -1 otherwise
 */
int chat_participant_get_position(OtrlListPtr participants_list, const char *accountname, unsigned int *position);

//TODO Dimitris: write docstring
int chat_participant_get_me_next_position(const char *accountname, OtrlListPtr participants_list, unsigned int *me_next);

/**
 Destroys the participants list of ctx

 This function accepts a context as an argument and destroys all the participants contained
 inside the function

 @param ctx The context whose participants list we wish to destroy
 @return void
 */
//void chat_participant_list_destroy(OtrlListNodeType ctx);

/**
 Calculates the hash of all the messages sent by a participant

 @param participant The participant whose messages will be hashed
 @param result A pointer pointing to an already allocated buffer that the hash
  result will be copied to

 @return 0 if no error occured. Non zero otherwise.
 */
int chat_participant_calculate_messages_hash(ChatParticipantPtr participant, unsigned char* result);

struct OtrlListOpsStruct chat_participant_listOps;

#endif /* CHAT_PARTICIPANT_H */
