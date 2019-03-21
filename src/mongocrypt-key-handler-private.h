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

#include "mongocrypt-key-decryptor.h"
#include "mongocrypt-buffer-private.h"

#define MONGOCRYPT_ENCRYPT 0
#define MONGOCRYPT_DECRYPT 1

void
_mongocrypt_key_init (mongocrypt_key_decryptor_t *kd,
                                _mongocrypt_buffer_t *key_material,
                                void *ctx,
                                const char *key_id,
                                int flag);

void
_mongocrypt_key_handler_cleanup (mongocrypt_key_decryptor_t *kd);
