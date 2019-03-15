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

#ifndef MONGOCRYPT_PRIVATE_H
#define MONGOCRYPT_PRIVATE_H

#include "mongocrypt.h"
#include "mongoc/mongoc.h"

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-key-cache-private.h"
#include "mongocrypt-mutex-private.h"
#include "mongocrypt-schema-cache-private.h"

#define MONGOCRYPT_GENERIC_ERROR_CODE 1

#define CLIENT_ERR_W_CODE(code, ...) \
   _mongocrypt_set_error (           \
      status, MONGOCRYPT_ERROR_TYPE_CLIENT, code, __VA_ARGS__)

#define CLIENT_ERR(...) \
   CLIENT_ERR_W_CODE (MONGOCRYPT_GENERIC_ERROR_CODE, __VA_ARGS__)

#define KMS_ERR_W_CODE(code, ...) \
   _mongocrypt_set_error (status, MONGOCRYPT_ERROR_TYPE_KMS, code, __VA_ARGS__)

#define KMS_ERR(...) KMS_ERR_W_CODE (MONGOCRYPT_GENERIC_ERROR_CODE, __VA_ARGS__)

/* TODO: consider changing this into a function */
#define MONGOCRYPTD_ERR_W_REPLY(bson_err, reply)                    \
   do {                                                             \
      if (bson_err.domain == MONGOC_ERROR_SERVER) {                 \
         _mongocrypt_set_error (status,                             \
                                MONGOCRYPT_ERROR_TYPE_MONGOCRYPTD,  \
                                bson_err.code,                      \
                                "%s",                               \
                                NULL);                              \
         if (reply) {                                               \
            status->ctx = bson_copy (reply);                        \
         }                                                          \
      } else { /* actually a client-side error. */                  \
         CLIENT_ERR_W_CODE (bson_err.code, "%s", bson_err.message); \
      }                                                             \
   } while (0)


/* TODO: remove after integrating into libmongoc */
#define BSON_SUBTYPE_ENCRYPTED 6

/* TODO: Move these to mongocrypt-log-private.h? */
const char *
tmp_json (const bson_t *bson);

const char *
tmp_buf (const _mongocrypt_buffer_t *buf);


void
_mongocrypt_set_error (mongocrypt_status_t *status,
                       mongocrypt_error_type_t type,
                       uint32_t code,
                       const char *format,
                       ...);

void
_bson_error_to_mongocrypt_error (const bson_error_t *bson_error,
                                 mongocrypt_error_type_t type,
                                 uint32_t code,
                                 mongocrypt_status_t *status);


// possible starting point for method
struct _mongocrypt_t {
   mongoc_client_pool_t *mongocryptd_pool;
   mongocrypt_opts_t *opts;
   mongocrypt_mutex_t mutex;
   _mongocrypt_schema_cache_t *schema_cache;
   /* The key cache has its own interal mutex. */
   _mongocrypt_key_cache_t *key_cache;
};

typedef struct {
   bson_iter_t v_iter;
   _mongocrypt_buffer_t iv;
   /* one of the following is zeroed, and the other is set. */
   _mongocrypt_buffer_t key_id;
   const bson_value_t *key_alt_name;
   const char *keyvault_alias;
} _mongocrypt_marking_t;

/* consider renaming to encrypted_w_metadata? */
typedef struct {
   _mongocrypt_buffer_t data;
   _mongocrypt_buffer_t iv;
   _mongocrypt_buffer_t key_id;
   const char *keyvault_alias; /* not null terminated. */
   uint16_t keyvault_alias_len;
} _mongocrypt_ciphertext_t;

bool
_mongocrypt_marking_parse_unowned (const _mongocrypt_buffer_t *in,
                                   _mongocrypt_marking_t *out,
                                   mongocrypt_status_t *status);
bool
_mongocrypt_ciphertext_parse_unowned (const bson_t *bson,
                                      _mongocrypt_ciphertext_t *out,
                                      mongocrypt_status_t *status);

bool
_mongocryptd_marking_reply_parse (const bson_t *bson,
                                  mongocrypt_request_t *request,
                                  mongocrypt_status_t *status);


typedef bool (*_mongocrypt_traverse_callback_t) (void *ctx,
                                                 _mongocrypt_buffer_t *in,
                                                 mongocrypt_status_t *status);


typedef bool (*_mongocrypt_transform_callback_t) (void *ctx,
                                                  _mongocrypt_buffer_t *in,
                                                  bson_value_t *out,
                                                  mongocrypt_status_t *status);


bool
_mongocrypt_traverse_binary_in_bson (_mongocrypt_traverse_callback_t cb,
                                     void *ctx,
                                     uint8_t match_first_byte,
                                     bson_iter_t *iter,
                                     mongocrypt_status_t *status);

bool
_mongocrypt_transform_binary_in_bson (_mongocrypt_transform_callback_t cb,
                                      void *ctx,
                                      uint8_t match_first_byte,
                                      bson_iter_t *iter,
                                      bson_t *out,
                                      mongocrypt_status_t *status);

#endif /* MONGOCRYPT_PRIVATE_H */
