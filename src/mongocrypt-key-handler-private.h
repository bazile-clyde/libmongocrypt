/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mongocrypt-buffer-private.h"
#include "kms_message/kms_decrypt_request.h"

#define MONGOCRYPT_ENCRYPT 0
#define MONGOCRYPT_DECRYPT 1

struct _mongocrypt_key_handler_t {
   kms_request_t *req;
   kms_response_parser_t *parser;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t msg;
   void *ctx;
};

void
_mongocrypt_key_handle_init (struct _mongocrypt_key_handler_t *kd,
                                _mongocrypt_buffer_t *key_material,
                                void *ctx,
                                const char *key_id,
                                int flag);

mongocrypt_binary_t *
_mongocrypt_key_handle_msg (struct _mongocrypt_key_handler_t *kd);

int
_mongocrypt_key_handle_bytes_needed (struct _mongocrypt_key_handler_t *kd,
                                       uint32_t max_bytes);

bool
_mongocrypt_key_handle_feed (struct _mongocrypt_key_handler_t *kd,
                               mongocrypt_binary_t *bytes);
void
_mongocrypt_key_handle_cleanup (struct _mongocrypt_key_handler_t *kd);

mongocrypt_status_t *
_mongocrypt_key_handle_status (struct _mongocrypt_key_handler_t *kd);
