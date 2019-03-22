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

#include "mongocrypt-binary-private.h"
#include "mongocrypt-key-handler-private.h"

void
_mongocrypt_key_handle_init (struct _mongocrypt_key_handler_t *kd,
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

mongocrypt_binary_t *
_mongocrypt_key_handle_msg (struct _mongocrypt_key_handler_t *kd)
{
   /* TODO testing, remove? */
   if (!kd) {
      return NULL;
   }

   if (kd->msg.data) {
      return _mongocrypt_buffer_to_binary (&kd->msg);
   }

   kd->msg.data = (uint8_t *) kms_request_get_signed (kd->req);
   kd->msg.len = (uint32_t) strlen ((char *) kd->msg.data);
   kd->msg.owned = true;
   return _mongocrypt_buffer_to_binary (&kd->msg);
}

int
_mongocrypt_key_handle_bytes_needed (struct _mongocrypt_key_handler_t *kd,
                                     uint32_t max_bytes)
{
   /* TODO test, change to assert later */
   if (!kd) {
      return 0;
   }
   return kms_response_parser_wants_bytes (kd->parser, (int32_t) max_bytes);
}

bool
_mongocrypt_key_handle_feed (struct _mongocrypt_key_handler_t *kd,
                             mongocrypt_binary_t *bytes)
{
   /* TODO: KMS error handling in CDRIVER-3000? */
   kms_response_parser_feed (kd->parser, bytes->data, bytes->len);
   return true;
}

mongocrypt_status_t *
_mongocrypt_key_handle_status (struct _mongocrypt_key_handler_t *kd)
{
   BSON_ASSERT (kd);

   return kd->status;
}

void
_mongocrypt_key_handle_cleanup (struct _mongocrypt_key_handler_t *kd)
{
   if (!kd) {
      return;
   }
   if (kd->req) {
      kms_request_destroy (kd->req);
   }
   if (kd->parser) {
      kms_response_parser_destroy (kd->parser);
   }
   mongocrypt_status_destroy (kd->status);
   _mongocrypt_buffer_cleanup (&kd->msg);
}
