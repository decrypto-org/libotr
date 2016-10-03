#include <gcrypt.h>
#include <stdio.h>

#include "chat_types.h"
#include "list.h"


int chat_participant_compare(PayloadPtr a, PayloadPtr b)
{
    OtrlChatParticipant *a1 = a;
    OtrlChatParticipant *b1 = b;

    return strcmp(a1->username, b1->username);
}

void chat_participant_free(OtrlChatParticipant *a)
{
    OtrlChatParticipant *a1 = a;

    free(a1->username);

    gcry_mpi_release(a1->signing_pub_key);

    free(a1);
}

void chat_participant_free_payload(PayloadPtr a)
{
    chat_participant_free(a);
}

void chat_participant_free_foreach(OtrlListNode *a)
{
    chat_participant_free(a->payload);
}

OtrlChatParticipant * chat_participant_create(const char *username, gcry_mpi_t pub_key)
{
    OtrlChatParticipant *participant;

    participant = malloc(sizeof(OtrlChatParticipant));
    if(!participant)
	return NULL;

    participant->username = strdup(username);
    if(pub_key)
	participant->signing_pub_key = gcry_mpi_copy(pub_key);
    else
	participant->signing_pub_key = gcry_mpi_new(320);

    return participant;
}

OtrlChatParticipant* chat_participant_find(OtrlChatContext *ctx, const char *username)
{
    OtrlListNode *foundListNode;
    OtrlChatParticipant *target;

    target = chat_participant_create(username, NULL);
    if(!target)
	return NULL;

    foundListNode = otrl_list_find(ctx->participants_list, target);
    chat_participant_free(target);

    if(!foundListNode)
	return NULL;

    return foundListNode->payload;
}

int chat_participant_add(OtrlList *list, const OtrlChatParticipant *participant)
{
    OtrlListNode *aNode;

    aNode = otrl_list_insert(list, (PayloadPtr)participant);

    if(!aNode)
	return 1;
    else
	return 0;
}

void chat_participant_list_destroy(OtrlList *list)
{
	otrl_list_foreach(list,chat_participant_free_foreach);
}

int chat_participant_list_from_usernames(OtrlList *participants, char **usernames, unsigned int usernames_size)
{
		char error = 0;
		OtrlChatParticipant *a_participant;
	    //OtrlChatMessage msg;

		fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: start\n");


	    error = 0;

	    fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: size: %d\n", usernames_size);
	    for(size_t i = 0; i < usernames_size; i++) {
	    	fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: adding %s\n", usernames[i]);
	    	a_participant = chat_participant_create(usernames[i],NULL);
	    	if(!a_participant){
	    		fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: username was not allocated\n");
	    		error = 1;
	    		break;
	    	}
	    	if(chat_participant_add(participants,a_participant)) {
	    		fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: participant not added\n");
	    		error = 1;
	    		break;
	    	}
	    }
	    if(error) {
	    	chat_participant_list_destroy(participants);
	    	return 1;
	    }

	    fprintf(stderr, "libotr-mpOTR: otrl_chat_participant_list_from_users: end\n");
	    return 0;
}

int chat_participant_get_position(const OtrlList *participants, const char *accountname)
{
	char *splitposition, *name;
	unsigned int i;
	OtrlListNode *cur;
	int ret = -1;

	name = NULL;

	//TODO Dimitris: this is a workaround, should be removed as soon as we find how to get the participant's account identifier instead of chat name
	splitposition = strchr(accountname, '@');
	if(splitposition) {
		name = malloc( (splitposition - accountname + 1) * sizeof *name);
		if(!name) {
			return 1;
		}
		memcpy(name, accountname, splitposition - accountname);
		name[splitposition - accountname] = '\0';
	} else {
		name = malloc( (strlen(accountname) + 1) * sizeof *name);
		strcpy(name, accountname);
	}

	if(participants) {
		for(cur = participants->head, i = 0; cur != NULL && strcmp(name, ((OtrlChatParticipant *)cur->payload)->username) != 0;  cur = cur->next, i++);
		if(cur)
			ret = i;
	}

	free(name);

	return ret;
}

int chat_participant_get_me_next_position(const char *accountname, const OtrlList *participants, unsigned int *me_next)
{
	char *splitposition, *name;
	unsigned int i;
	OtrlListNode *cur;
	int err = 0;

	fprintf(stderr, "libotr-mpOTR: chat_participant_get_me_next_position: start\n");

	name = NULL;

	//TODO Dimitris: this is a workaround, should be removed as soon as we find how to get the participant's account identifier instead of chat name
	fprintf(stderr, "libotr-mpOTR: chat_participant_get_me_next_position: before splitposition\n");
	splitposition = strchr(accountname, '@');
	if(splitposition) {
		fprintf(stderr, "libotr-mpOTR: chat_participant_get_me_next_position: before malloc\n");
		name = malloc( (splitposition - accountname + 1) * sizeof *name);
		if(!name) {
			return 1;
		}
		memcpy(name, accountname, splitposition - accountname);
		name[splitposition - accountname] = '\0';
	} else {
		fprintf(stderr, "libotr-mpOTR: chat_participant_get_me_next_position: before strcpy\n");
		strcpy(name, accountname);
	}

	fprintf(stderr, "libotr-mpOTR: chat_participant_get_me_next_position: before if(participants_list)\n");
	if(participants) {
		i = 0;
		for(cur = participants->head; cur != NULL && strcmp(name, ((OtrlChatParticipant *)cur->payload)->username) != 0;  cur = cur->next) {
			i++;
		}
		if(cur) {
			me_next[0] = i;
			me_next[1] = (cur->next) ? i+1 : 0;
		} else {
			err = 1;
		}
	}

	free(name);

	fprintf(stderr, "libotr-mpOTR: chat_participant_get_me_next_position: end\n");

	return err;
}

void chat_participant_toString(OtrlListNode *node)
{
    OtrlChatParticipant *participant = node->payload;
    unsigned char *buf;
    size_t s;

    gcry_mpi_print(GCRYMPI_FMT_HEX, NULL, 0, &s, participant->signing_pub_key);
    buf = malloc((s+1)*sizeof(*buf));
    gcry_mpi_print(GCRYMPI_FMT_HEX, buf, s, NULL, participant->signing_pub_key);
    fprintf(stderr, "OtrlChatParticipant:\n");
    fprintf(stderr, "|-username\t:%s\n",participant->username);
    fprintf(stderr, "|-pub_key\t:%s\n", buf);

    free(buf);
}

struct OtrlListOpsStruct chat_participant_listOps = {
    chat_participant_compare,
    chat_participant_toString,
    chat_participant_free_payload
};
