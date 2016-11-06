#ifndef CHAT_SHUTDOWN_H
#define CHAT_SHUTDOWN_H

#include "chat_types.h"

typedef enum {
	CHAT_SHUTDOWNSTATE_NONE,
	CHAT_SHUTDOWNSTATE_AWAITING_SHUTDOWNS,
	CHAT_SHUTDOWNSTATE_AWAITING_DIGESTS,
	CHAT_SHUTDOWNSTATE_AWAITING_ENDS,
	CHAT_SHUTDOWNSTATE_FINISHED
} ChatShutdownState;

ChatShutdownState chat_shutdown_info_get_state(ChatShutdownInfoPtr shutdown_info);
void chat_shutdown_info_free(ChatShutdownInfoPtr shutdown_info);

/**
 Initializes the shutdown subprotocol

 @param ctx The context we are initializing the shutdown subprotocol for
 @return Non-zero on error. Zero on success
*/
int chat_shutdown_init(ChatContextPtr ctx);

/**
 Sends a shutdown message

 @param ctx The context for this protocol run
 @param msgToSend On success *msgToSend will point to a newly created
  shutdown message that must be sent in the chatroom
 @return Non-zero on error. Zero on success.
*/
int chat_shutdown_send_shutdown(ChatContextPtr ctx, ChatMessage **msgToSend);

/**
 Sends a digest message

 @param ctx The context for this protocol run
 @param msgToSend On success *msgToSend will point to a newly created
  digest message that must be sent in the chatroom
 @return Non-zero on error. Zero on success

 */
int chat_shutdown_send_digest(ChatContextPtr ctx, ChatMessage **msgToSend);

/**
 Sends an end message

 @param ctx The context for this protocol run
 @param msgToSend On success *msgToSend will point to a newly created
  end message that must be sent in the chatroom
 @return Non-zero on error. Zero on success
*/
int chat_shutdown_send_end(ChatContextPtr ctx, ChatMessage **msgToSend);

/**
 Sends a key release message

 @param ctx The context for this protocol run
 @param msgToSend On success *msgToSend will point to a newly created
  key release message that must be sent in the chatroom
 @return Non-zero on error. Zero on success
*/
int chat_shutdown_release_secrets(ChatContextPtr ctx, ChatMessage **msgToSend);

/**
 Checks if a message belongs in the shutdown protocol

 If a non-zero value is returned the message must then be passed in the
 chat_shutdown_handle_message function to be handled.

 @param msg The message to be checked
 @return Non-zero if the message belongs to the protocol. Zero if it does not
*/
int chat_shutdown_is_my_message(const ChatMessage *msg);

/**
 Handles a message belonging in the shutdown subprotocol

 @param ctx The context for this protocol run
 @param msg The message received
 @param msgToSend If the function call is successful and *msgToSend is not NULL
  then *msgToSend will point to a message of the shutdown subprotocol that must
  be sent in the chatroom
 @return Zero on success. Non-zero on error
*/
int chat_shutdown_handle_message(ChatContextPtr ctx, ChatMessage *msg,
		                 ChatMessage **msgToSend);

#endif /* CHAT_SHUTDOWN_H */
