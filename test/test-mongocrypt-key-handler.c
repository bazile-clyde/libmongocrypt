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

#include <mongocrypt-key-handler-private.h>
#include <regex.h>

#include "test-mongocrypt.h"

static void
_test_key_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_key_decryptor_t *key;
   _mongocrypt_buffer_t *key_material;
   void *ctx = NULL;
   char *request;
   regex_t regex;

   key = bson_malloc0 (sizeof (*key));
   key_material = bson_malloc0 (sizeof (*key_material));

   _mongocrypt_key_handle_init (
      key, key_material, ctx, NULL, MONGOCRYPT_DECRYPT);
   request = kms_request_get_canonical (key->req);

   BSON_ASSERT (0 == regcomp (&regex,
                              "x-amz-target[\\s]*:[\\s]*trentservice.DECRYPT",
                              REG_ICASE));
   BSON_ASSERT (0 == regexec (&regex, request, 0, NULL, 0));

   _mongocrypt_key_decryptor_cleanup (key);
   _mongocrypt_buffer_cleanup (key_material);

   key = bson_malloc0 (sizeof (*key));
   key_material = bson_malloc0 (sizeof (*key_material));

   _mongocrypt_key_handle_init (
      key, key_material, ctx, "alias/1", MONGOCRYPT_ENCRYPT);
   request = kms_request_get_canonical (key->req);

   BSON_ASSERT (0 == regcomp (&regex,
                              "x-amz-target[\\s]*:[\\s]*trentservice.ENCRYPT",
                              REG_ICASE));
   BSON_ASSERT (0 == regexec (&regex, request, 0, NULL, 0));

   _mongocrypt_key_decryptor_cleanup (key);
   _mongocrypt_buffer_cleanup (key_material);
}

void
_mongocrypt_tester_install_key_handler (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_key_init);
}