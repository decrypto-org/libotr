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

/**
 Compare two participants

 This function compares two participants a and b which are passed as
 payload pointers. It returns a < b.

 @param a the first participant to compare
 @param b the second participant to compare

 @return 0 on equality, 1 if a < b and -1 if a >= b
 */
int chat_participant_compare(PayloadPtr a, PayloadPtr b);

/**
  Free a pariticpant

  This function frees the participant a, and any data
  within the participant

  @param a The participant to be free'd

  @return void
 */
void chat_participant_destroy(ChatParticipant a);

/**
  Create a new participant

  This function creates a new participant with username as his user name
  and pub_key as his public signing key

  @param username The user's user name
  @param pub_key The user's public key needed to verify the user's signatures

  @return A pointer to the newly created participant
 */
ChatParticipant* chat_participant_create(const char *username, gcry_mpi_t pub_key);

/**
  Find a participant in the ctx context's participants list

  This function searches the participants list in ctx to find the user with the specifed
  user name

  @param ctx The context where the user will be searched
  @param username The user name of the user to be searced
  @param position If the user is found the position contains his position in the list

  @return If the user is found a pointer to it will be returned. Otherwise NULL
 */
ChatParticipant* chat_participant_find(OtrlChatContext *ctx, const char *username, unsigned int *position);

/**
  Add a user to the ctx's participants list

  This function will add a new user defined in participant in the ctx's participants list

  @param ctx The context where we will add the user
  @param participan The user to be added

  @return 1 if the user was sucessfully added. 0 otherwise.
 */
int chat_participant_add(OtrlChatContext ctx,const ChatParticipant *participant);

/**
 Add a group of usernames in a list

 This function takes a participant list and adds usernames_size usernames contained in usernames

 @param participants The list where the participants will be added
 @param usernames An array of null termintated user names
 @param usernames_size the lenght of the usernames array

 @return 0 if there was no error. 1 otherwise
 */
int chat_participant_list_from_usernames(OtrlList *participants, char **usernames, unsigned int usernames_size);


/**
 Get the position of an accountname in a list

 @param participants The list of the participants
 @param accountname The account name we are searching for
 @param position If found, contains the position of the participant in the list

 @return 0 if found. -1 otherwise
 */
int chat_participant_get_position(const OtrlList *participants, const char *accountname, unsigned int *position);

//TODO Dimitris: write docstring
int chat_participant_get_me_next_position(const char *accountname, const OtrlList *participants, unsigned int *me_next);

/**
 Destroys the participants list of ctx

 This function accepts a context as an argument and destroys all the participants contained
 inside the function

 @param ctx The context whose participants list we wish to destroy
 @return void
 */
void chat_participant_list_destroy(OtrlListNode ctx);

/**
 Calculates the hash of all the messages sent by a participant

 @param participant The participant whose messages will be hashed
 @param result A pointer pointing to an already allocated buffer that the hash
  result will be copied to

 @return 0 if no error occured. Non zero otherwise.
 */
int chat_participant_get_messages_hash(ChatParticipant *participant, unsigned char* result);

struct OtrlListOpsStruct chat_participant_listOps;

#endif /* CHAT_PARTICIPANT_H */
