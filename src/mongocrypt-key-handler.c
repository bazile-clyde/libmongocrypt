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

#include "mongocrypt-key-decryptor.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-key-decryptor-private.h"
#include "mongocrypt-key-handler-private.h"

void
_mongocrypt_key_init (mongocrypt_key_decryptor_t *kd,
                                _mongocrypt_buffer_t *key_material,
                                void *ctx,
                                const char *key_id,
                                int flag)
{
   kms_request_opt_t *opt;
   /* create the KMS request. */
   opt = kms_request_opt_new ();
   /* TODO: we might want to let drivers control whether or not we send
      * Connection: close header. Unsure right now. */
   kms_request_opt_set_connection_close (opt, true);
   if (flag == MONGOCRYPT_DECRYPT) {
      kd->req =
         kms_decrypt_request_new (key_material->data, key_material->len, opt);
   } else if (flag == MONGOCRYPT_ENCRYPT) {
      kd->req = kms_encrypt_request_new (
         key_material->data, key_material->len, key_id, opt);
   }
   kd->parser = kms_response_parser_new ();
   kd->ctx = ctx;

   kd->status = mongocrypt_status_new ();
   _mongocrypt_buffer_init (&kd->msg);
   kms_request_opt_destroy (opt);
}
