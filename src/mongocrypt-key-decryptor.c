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

#include "kms_message/kms_request_opt.h"

#include "mongocrypt-binary-private.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-key-decryptor.h"
#include "mongocrypt-key-decryptor-private.h"
#include "mongocrypt-key-handler-private.h"

void
_mongocrypt_key_decryptor_init (mongocrypt_key_decryptor_t *kd,
                                _mongocrypt_buffer_t *key_material,
                                void *ctx)
{
   _mongocrypt_key_handle_init (kd, key_material, ctx, NULL, MONGOCRYPT_DECRYPT);
}

mongocrypt_binary_t *
mongocrypt_key_decryptor_msg (mongocrypt_key_decryptor_t *kd)
{
   return _mongocrypt_key_handle_msg (kd);
}


int
mongocrypt_key_decryptor_bytes_needed (mongocrypt_key_decryptor_t *kd,
                                       uint32_t max_bytes)
{
   return _mongocrypt_key_handle_bytes_needed (kd, max_bytes);
}


bool
mongocrypt_key_decryptor_feed (mongocrypt_key_decryptor_t *kd,
                               mongocrypt_binary_t *bytes)
{
   return _mongocrypt_key_handle_feed (kd, bytes);
}

mongocrypt_status_t *
mongocrypt_key_decryptor_status (mongocrypt_key_decryptor_t *kd)
{
   BSON_ASSERT (kd);

   return kd->status;
}

void
_mongocrypt_key_decryptor_cleanup (mongocrypt_key_decryptor_t *kd)
{
   _mongocrypt_key_handle_cleanup(kd);
}
