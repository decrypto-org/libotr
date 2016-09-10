#ifndef CHAT_SHUTDOWN_H
#define CHAT_SHUTDOWN_H

#include "chat_types.h"

int chat_shutdown_init(OtrlChatContext *ctx);

int chat_shutdown_send_shutdown(OtrlChatContext *ctx, ChatMessage **msgToSend);

int chat_shutdown_send_digest(OtrlChatContext *ctx, ChatMessage **msgToSend);

int chat_shutdown_send_end(OtrlChatContext *ctx, ChatMessage **msgToSend);

int chat_shutdown_release_secrets(OtrlChatContext *ctx, ChatMessage **msgToSend);


int chat_shutdown_is_my_message(const ChatMessage *msg);

int chat_shutdown_handle_message(OtrlChatContext *ctx, ChatMessage *msg,
		                 ChatMessage **msgToSend);


#endif /* CHAT_SHUTDOWN_H */
