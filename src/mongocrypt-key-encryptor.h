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

#include "mongocrypt-binary.h"
#include "mongocrypt-status.h"
#include "mongocrypt-key-handler-private.h"

/* Represents a request/response parser for the encryptor of a key material. */
typedef struct _mongocrypt_key_handler_t mongocrypt_key_encryptor_t;

MONGOCRYPT_EXPORT
mongocrypt_binary_t *
mongocrypt_key_encryptor_msg (mongocrypt_key_encryptor_t *kd);

MONGOCRYPT_EXPORT
int
mongocrypt_key_encryptor_bytes_needed (mongocrypt_key_encryptor_t *kd,
                                       uint32_t max_bytes);

MONGOCRYPT_EXPORT
bool
mongocrypt_key_encryptor_feed (mongocrypt_key_encryptor_t *kd,
                               mongocrypt_binary_t *bytes);

MONGOCRYPT_EXPORT
mongocrypt_status_t *
mongocrypt_key_encryptor_status (mongocrypt_key_encryptor_t *kd);