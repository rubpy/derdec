#ifndef DERDEC_H
#define DERDEC_H

// clang-format off

/****************************************************************************
 *
 * MIT License
 *
 * Copyright (c) 2022 by rubpy / pr3
 * (https://github.com/rubpy/derdec)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 ****************************************************************************/

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *              888                      888
 *              888                      888
 *              888                      888
 *          .d88888  .d88b.  888d888 .d88888  .d88b.   .d8888b
 *         d88" 888 d8P  Y8b 888P"  d88" 888 d8P  Y8b d88P"
 *         888  888 88888888 888    888  888 88888888 888
 *         Y88b 888 Y8b.     888    Y88b 888 Y8b.     Y88b.
 *          "Y88888  "Y8888  888 ... "Y88888  "Y8888   "Y8888P
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

/**
 * @file derdec.h
 * @brief A silly single-header library for extracting (decoding)
 *        modulus N & exponent E arbitrary-precision integers from
 *        ASN.1 DER-encoded RSA public keys.
 *
 * @warning Yeah, don't use this in production, or wherever you need
 *          field-tested cryptographic security.
 *
 * Compiled and tested on gcc 12.1.0 & clang 14.0.6:
 * ```
 * gcc
 *   -std=c99
 *   -Wall -Wextra -pedantic
 *   -fsanitize=address -fsanitize=undefined
 *   -Ofast
 * ```
 */

/* Example code:
   ```c

   #include <derdec.h>

   #include <stdint.h>
   #include <stdio.h>
   #include <string.h>

   // The byte array below (i.e., raw public key) corresponds to this string
   // when encoded in Base64:
   //
   // MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkAiVVmn5z1uj6mv+cycL
   // +e2sYPsnh/PhOnwStLSPv0lTKK0O7Ery1MebnHH3a14syNMDI7qxyF0oAR48//XS
   // imxSx8kCwbjLhHTYpmDuZGEliU6C2+hn6dkTpMImkieS1N5ciyroxerTqjuedFcA
   // tYPMotDc1yovNlbazedfyBPsIQqPyx9RDRnsUVx4hYdMUx6yK2YYhuAiPhP0uocE
   // xPzhc+M/qTFXwcTylmeyLpvI/7AUocCRusTfe2NPMtQUuttCVEeICjcoIYnV+LGu
   // 0O/tJzJ2l+X/QkRF1jrTj9cdHqWFuXrVEf75DhMoJKUlB5I6cEHJ3u3KM+fNmi4E
   // zwIDAQAB
   //

   const uint8_t sample_raw_pkey[] = {
       0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
       0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
       0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xbe, 0xe6, 0x8e,
       0xe0, 0xb0, 0x8a, 0xba, 0x5e, 0xc9, 0x30, 0x4d, 0x92, 0xc9, 0xa2, 0x5d,
       0xe8, 0xbd, 0x9c, 0x10, 0x15, 0x66, 0xd7, 0xfc, 0xbf, 0x18, 0x6c, 0x09,
       0x83, 0x80, 0x6a, 0x36, 0x4b, 0x9f, 0x84, 0x4e, 0x5e, 0x1b, 0xa2, 0xed,
       0xcb, 0x7e, 0xc4, 0x85, 0x84, 0x7f, 0x87, 0x4f, 0xb7, 0x4d, 0x85, 0xed,
       0x38, 0x66, 0x4e, 0x65, 0x50, 0x78, 0xb9, 0xac, 0xcf, 0x92, 0x6d, 0xd7,
       0x37, 0x1a, 0xf2, 0xd1, 0x07, 0xb6, 0x3d, 0x95, 0x1a, 0x79, 0xfe, 0x78,
       0x83, 0x7d, 0x14, 0x8e, 0xf5, 0x89, 0x23, 0xe4, 0x90, 0xd2, 0xb5, 0x31,
       0xdf, 0x9b, 0x7e, 0xf9, 0xbb, 0x3c, 0xd1, 0xcd, 0xba, 0x78, 0xd7, 0x65,
       0xa1, 0xa7, 0xb7, 0xaa, 0x27, 0xa3, 0xe6, 0x8d, 0xe1, 0xdb, 0x7d, 0x9d,
       0x52, 0x5b, 0x3d, 0x55, 0x3a, 0xd6, 0xf8, 0xf4, 0xa0, 0x6d, 0xfb, 0xff,
       0x87, 0xc8, 0xb7, 0x7f, 0xb1, 0x34, 0x9b, 0xad, 0xe5, 0xf0, 0xa6, 0xd6,
       0x36, 0x00, 0x45, 0xe5, 0x50, 0xb5, 0x78, 0x4a, 0x16, 0xf4, 0x0c, 0xba,
       0x4d, 0x72, 0xcd, 0x02, 0xc2, 0x1e, 0x74, 0x71, 0x03, 0x6e, 0x2d, 0xdb,
       0x9d, 0x76, 0x63, 0x6d, 0xe8, 0xf6, 0x85, 0x44, 0xf3, 0xc0, 0x58, 0x35,
       0xbd, 0xfd, 0x93, 0xbc, 0x72, 0xaa, 0x70, 0x6c, 0xad, 0x08, 0x0c, 0x80,
       0x90, 0x97, 0xe3, 0x41, 0x7f, 0x57, 0x66, 0xf0, 0xb5, 0x46, 0xa3, 0x0e,
       0x87, 0x4f, 0x83, 0x03, 0x61, 0x1c, 0x7c, 0xb2, 0xb2, 0xb0, 0x0e, 0xd0,
       0xe9, 0xc6, 0x9b, 0xdb, 0x7a, 0x1b, 0x50, 0x89, 0x2f, 0x1d, 0xfc, 0xe5,
       0xf1, 0x0e, 0x73, 0xdf, 0xc7, 0x2b, 0x03, 0xa2, 0x87, 0x55, 0xa5, 0x78,
       0xac, 0x58, 0xfd, 0x6f, 0x0e, 0xe4, 0x36, 0x9b, 0x78, 0xc3, 0x8b, 0xe1,
       0x79, 0xd6, 0xf2, 0x33, 0x31, 0x4e, 0xf0, 0xbe, 0xe5, 0x39, 0x05, 0x44,
       0xcb, 0x02, 0x03, 0x01, 0x00, 0x01,
   };
   const size_t sample_raw_pkey_len = sizeof(sample_raw_pkey);

   void print_hex(const uint8_t *data, size_t data_len) {
     if (data == NULL || data_len == 0) {
       return;
     }

     for (size_t i = 0; i < data_len; ++i) {
       printf("%c%02x",
              (char)(((~((i - 1) >> 63) & 1) * 10) ^
                     (((i | (i >> 1) | (i >> 2)) & 1) * 42)),
              data[i]);
     }
     putchar('\n');
   }

   int main(void) {
     derdec_pkey pkey;

     derdec_err err;
     if ((err = derdec_decode_pkey(&pkey, sample_raw_pkey, sample_raw_pkey_len)) !=
         DERDEC_OK) {
       fprintf(stderr, "[!] derdec_decode_pkey failed: %s\n", derdec_err_str(err));
       return 1;
     }

     if (!derdec_pkey_is_pkcs1(&pkey)) {
       fprintf(stderr, "[!] pkey is not a PKCS1 public key\n");
       return 2;
     }

     // --------------------------------------------------

     puts("modulus:");
     print_hex(derdec_pkey_modulus(&pkey), derdec_pkey_modulus_size(&pkey));
     putchar('\n');

     puts("exponent:");
     print_hex(derdec_pkey_exponent(&pkey), derdec_pkey_exponent_size(&pkey));

     return 0;
   }

   ```
*/

// clang-format on

#include <limits.h>  // UINT_MAX
#include <stdbool.h> // bool, true, false
#include <stddef.h>  // size_t, NULL
#include <stdint.h>  // uint8_t, uint32_t, uint64_t...
#include <string.h>  // memcpy, memset, memcmp

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================== */
/* ================================================== */
/* ================================================== */

/**
 * A list of all possible status codes/return values returned by common
 * functions of the API.
 *
 * A zero, or `DERDEC_OK`, indicates success (i.e., no error).
 *
 * NOTE: for dynamic translation of 'error value' to 'error string
 * representation', see: `derdec_err_str`.
 */
typedef enum derdec_err {
  DERDEC_OK = 0x0000,

  DERDEC_MISUSE = 0x0001,      // improper API usage
  DERDEC_EOF = 0x0002,         // unexpected end of data
  DERDEC_UNSUPPORTED = 0x0003, // unsupported data type
  DERDEC_MALFORMED = 0x0004,   // malformed data

  DERDEC_PKEY_SIGNATURE = 0x0010, // missing public key signature
  DERDEC_PKEY_MALFORMED = 0x0014, // malformed public key contents

  DERDEC_RSA_TOOLONG = 0x0100, // RSA message too long
} derdec_err;

/**
 * Returns an 'error string representation' for a given 'error value'.
 *
 * For example, returns "ok" for `DERDEC_OK`, and "RSA message too long" for
 * `DERDEC_RSA_TOOLONG`.
 *
 * NOTE: this function will return an empty string (""), if an incorrect 'error
 * value' is given.
 */
const char *derdec_err_str(const enum derdec_err err);

/* -------------------------------------------------- */

/**
 * Possible (recognized) types of DER TLV's.
 *
 * NOTE: only a subset of these is used/supported.
 */
typedef enum derdec_tlv_type {
  DERDEC_TLV_INTEGER = 0x02,
  DERDEC_TLV_BITSTRING = 0x03,
  DERDEC_TLV_OCTETSTRING = 0x04,
  DERDEC_TLV_NULL = 0x05,
  DERDEC_TLV_OBJECT = 0x06,

  DERDEC_TLV_UTF8STRING = 0x0C,
  DERDEC_TLV_PRINTABLESTRING = 0x13,
  DERDEC_TLV_IA5STRING = 0x16,

  DERDEC_TLV_UTCTIME = 0x17,
  DERDEC_TLV_GENERALIZEDTIME = 0x18,

  DERDEC_TLV_SEQUENCE = 0x30,
  DERDEC_TLV_SET = 0x31,
} derdec_tlv_type;

/**
 * Wrapper for an individual TLV (type-length-value)-encoded item contained
 * within a raw public key.
 *
 * It is valid so long as the original, underlying array of bytes (e.g., parser
 * input) stays valid.
 */
typedef struct derdec_tlv {
  /**
   * Type of the TLV.
   *
   * See `enum derdec_tlv_type` for a list of possible values.
   */
  derdec_tlv_type type;

  /**
   * An additional parameter associated with the TLV.
   *
   * Generally, unused and equal to zero. In the case of, e.g., `BITSTRING`, it
   * is set to the number of 'unused bits'.
   */
  uint32_t param;

  /**
   * Pointer to the first byte of TLV's raw contents in memory.
   *
   * NOTE: this pointer is valid only for the lifetime of the parent data block.
   * WARNING: this is not a null-terminated C string. Do not use `printf` format
   * specifier "%s" to dump its contents.
   */
  const uint8_t *start;

  /**
   * Pointer to a byte just past the end of TLV's raw contents in memory.
   *
   * The contents of a TLV span (left-inclusive, right-exclusive) between:
   * [start, end).
   *
   *           ╔─ CONTENTS ───────────────────────╗
   * ┌────┬────║────┬────┬────┬────┬────┬────┬────║────┬────┬────┬────┐
   * │ 05 │ 93 ║ 1a │ e6 │ 14 │ 06 │ c5 │ 00 │ 7f ║ ff │ 80 │ 1f │ 00 │
   * └────┴────╚─┬──┴────┴────┴────┴────┴────┴────╝─┬──┴────┴────┴────┘
   *             │                                  │
   *             ⇑                                  ⇑
   *           start                               end
   *
   ***********************************************************************
   *
   * WARNING: this pointer cannot be dereferenced. The last valid byte of
   * contents is located at `(end - 1)`, not `end` itself.
   */
  const uint8_t *end;
} derdec_tlv;

/**
 * Returns a string representation for the given TLV `type`.
 *
 * For example, returns "SEQUENCE" for `DERDEC_TLV_SEQUENCE` (0x30).
 *
 * NOTE: an empty string ("") is returned for invalid/unrecognized type values.
 */
const char *derdec_tlv_type_str(enum derdec_tlv_type type);

/**
 * Decodes a range of bytes, `[*data_curr, data_end)`, as an ASN.1 DER-encoded
 * TLV item.
 * `data_curr` is a pointer to a variable, which itself contains a pointer to
 * the beginning of a (presumed) TLV.
 * `data_end` is a pointer to the end (or, byte just past the end) of a buffer.
 * Hence, the decoder is going to start at `*data_curr`, and if it ever reaches
 * `data_end` 'in the middle' of a TLV, it is going to fail with `DERDEC_EOF`.
 *
 * On success, the decoded TLV is saved in `result`, and `DERDEC_OK` (0) is
 * returned.
 * Additionally, `data_curr` is updated with a pointer to the byte just past the
 * end of this TLV. In other words, `data_curr` is set to what might be the
 * beginning of the next TLV. Due to this behavior, this function can be called
 * repeatedly in order to decode a list of consecutive TLV's within a
 * bytestream.
 *
 * On error, returns a non-zero value (see `enum derdec_err` and
 * `derdec_err_str`).
 *
 * NOTE: if `result` == NULL, `data_curr` == NULL, `*data_curr == NULL`, or
 * `data_end` == 0, an error is returned.
 *
 * NOTE: if `result` != NULL, and an error occurs while decoding, contents of
 * `result` are zeroed out explicitly.
 */
derdec_err derdec_decode_tlv(derdec_tlv *result, const uint8_t **data_curr,
                             const uint8_t *data_end);

/* -------------------------------------------------- */

/**
 * Representation of a parsed public key.
 */
typedef struct derdec_pkey {
  derdec_tlv object_id;
  derdec_tlv modulus;
  derdec_tlv exponent;
} derdec_pkey;

/**
 * Returns a pointer to (raw bytes of) the modulus of public key `pkey`, or NULL
 * if `pkey` is invalid.
 *
 * NOTE: see `derdec_pkey_modulus_size` to know how many bytes can be accessed.
 */
const uint8_t *derdec_pkey_modulus(const derdec_pkey *const pkey);

/**
 * Returns the size of the modulus of public key `pkey`, or 0 if `pkey` is
 * invalid.
 */
size_t derdec_pkey_modulus_size(const derdec_pkey *const pkey);

/**
 * Returns a pointer to (raw bytes of) the exponent of public key `pkey`, or
 * NULL if `pkey` is invalid.
 *
 * NOTE: see `derdec_pkey_exponent_size` to know how many bytes can be accessed.
 */
const uint8_t *derdec_pkey_exponent(const derdec_pkey *const pkey);

/**
 * Returns the size of the exponent of public key `pkey`, or 0 if `pkey` is
 * invalid.
 */
size_t derdec_pkey_exponent_size(const derdec_pkey *const pkey);

/**
 * Returns whether a PKCS#1 'OBJECT' object identifier signature could be found
 * in the encoded public key `pkey`.
 *
 * Signature: [2a 86 48 86 f7 0d 01 01 01]
 * (see: page 55, RFC 3447)
 */
bool derdec_pkey_is_pkcs1(const derdec_pkey *const pkey);

/**
 * Decodes a stream of bytes, `data`, of length `data_len`, as an ASR.1
 * DER-encoded RSA public key.
 *
 * On success, the result is saved in `result`, and `DERDEC_OK` (0) is returned.
 * On error, returns a non-zero value (see `enum derdec_err` and
 * `derdec_err_str`).
 *
 * NOTE: if `result` == NULL, `data` == NULL, or `data_len` == 0, an error is
 * returned.
 *
 * NOTE: if `result` != NULL, and an error occurs while parsing, contents of
 * `result` are zeroed out explicitly.
 */
derdec_err derdec_decode_pkey(derdec_pkey *result, const uint8_t *data,
                              size_t data_len);

/* -------------------------------------------------- */

/**
 * Encodes byte array `plaintext` of length `plaintext_len` as a valid PKCS#1
 * v1.5-padded RSA input, and saves the encoded (not encrypted!) result in
 * buffer `buf` of length `buf_len` (i.e., only so many bytes can be stored in
 * the buffer).
 * Although `prng_seed` is an optional parameter (pass 0 by default), ideally it
 * should be a 32-bit cryptographically secure source of entropy.
 *
 * On success, the result is saved in `buf`, and `DERDEC_OK` (0) is returned.
 * On error, returns a non-zero value (see `enum derdec_err` and
 * `derdec_err_str`).
 *
 * NOTE: if `buf` == NULL, `buf_len` == 0, `plaintext` == NULL, or
 * `plaintext_len` == 0, an error is returned.
 *
 * NOTE: if `buf` != NULL (and `buf_len` > 0), and an error occurs while
 * encoding, contents of `buf` are zeroed out explicitly.
 */
derdec_err derdec_pkcs1(uint8_t *buf, size_t buf_len, const uint8_t *plaintext,
                        size_t plaintext_len, uint32_t prng_seed);

/* ================================================== */
/* ================================================== */
/* ================================================== */

#ifndef DERDEC_NO_IMPL

const char *derdec_err_str(const enum derdec_err err) {
  switch (err) {
  case DERDEC_OK:
    return "ok";

  case DERDEC_MISUSE:
    return "misuse";
  case DERDEC_EOF:
    return "EOF";
  case DERDEC_UNSUPPORTED:
    return "unsupported";
  case DERDEC_MALFORMED:
    return "malformed";

  case DERDEC_PKEY_SIGNATURE:
    return "missing public key signature";
  case DERDEC_PKEY_MALFORMED:
    return "malformed public key contents";

  case DERDEC_RSA_TOOLONG:
    return "RSA message too long";
  }

  return "";
}

/* -------------------------------------------------- */

struct derdec_tlv_type_strlookup_entry {
  const char *str;
  derdec_tlv_type type;
};

static const struct derdec_tlv_type_strlookup_entry
    derdec_tlv_type_strlookup[] = {
        {"INTEGER", DERDEC_TLV_INTEGER},
        {"BITSTRING", DERDEC_TLV_BITSTRING},
        {"OCTETSTRING", DERDEC_TLV_OCTETSTRING},
        {"NULL", DERDEC_TLV_NULL},
        {"OBJECT", DERDEC_TLV_OBJECT},
        {"UTF8STRING", DERDEC_TLV_UTF8STRING},
        {"PRINTABLESTRING", DERDEC_TLV_PRINTABLESTRING},
        {"IA5STRING", DERDEC_TLV_IA5STRING},
        {"UTCTIME", DERDEC_TLV_UTCTIME},
        {"GENERALIZEDTIME", DERDEC_TLV_GENERALIZEDTIME},
        {"SEQUENCE", DERDEC_TLV_SEQUENCE},
        {"SET", DERDEC_TLV_SET},
};

const char *derdec_tlv_type_str(enum derdec_tlv_type type) {
  static const size_t derdec_tlv_type_strlookup_count =
      sizeof(derdec_tlv_type_strlookup) / sizeof(derdec_tlv_type_strlookup)[0];

  for (size_t i = 0; i < derdec_tlv_type_strlookup_count; ++i) {
    if (derdec_tlv_type_strlookup[i].type == type) {
      return derdec_tlv_type_strlookup[i].str;
    }
  }

  return "";
}

derdec_err derdec_decode_tlv(derdec_tlv *result, const uint8_t **data_curr,
                             const uint8_t *data_end) {
  if (result == NULL) {
    return DERDEC_MISUSE;
  }

  memset(result, 0, sizeof(*result));

  if (data_curr == NULL || data_end == NULL) {
    return DERDEC_MISUSE;
  }

  const uint8_t *curr = *data_curr;
  if (curr == NULL || curr >= data_end) {
    return DERDEC_MISUSE;
  }

  derdec_err ret = DERDEC_EOF;

  uint32_t param = 0;
  uint8_t type = 0;
  uint8_t len_short = 0;
  size_t len_long = 0;

  const uint8_t *len_long_end = NULL;
  const uint8_t *value_end = NULL;

  type = *curr++;
  if (curr >= data_end)
    goto stop_decoding;

  len_short = *curr++;
  if (curr >= data_end)
    goto stop_decoding;

  if (len_short == 0x80) {
    ret = DERDEC_MALFORMED;
    goto stop_decoding;
  } else if (len_short > 0x80) {
    len_short -= 0x80;

    // NOTE: this is platform-dependent. For example, `sizeof(size_t)` would
    // probably be 4 on an ESP8266, but 8 on 64-bit modern PCs.
    if (len_short > sizeof(size_t)) {
      ret = DERDEC_UNSUPPORTED;

      goto stop_decoding;
    }

    len_long_end = (curr + (size_t)len_short);
    if (len_long_end >= data_end) {
      goto stop_decoding;
    }

    for (; curr < len_long_end; ++curr) {
      len_long = ((len_long << 8) | (size_t)*curr);
    }
  } else {
    len_long = (size_t)len_short;
  }

  value_end = (curr + len_long);
  if (value_end > data_end) {
    goto stop_decoding;
  }

  if (type == 0x03) {
    // If TLV is a 'BITSTRING', we need to extract an extra parameter.

    if (curr >= value_end) {
      goto stop_decoding;
    }

    param = (uint32_t)*curr++;
  }

  result->type = (derdec_tlv_type)type;
  result->param = param;
  result->start = curr;
  result->end = value_end;

  ret = DERDEC_OK;

  curr = value_end;

stop_decoding:
  *data_curr = curr;

  return ret;
}

/* -------------------------------------------------- */

const uint8_t *derdec_pkey_modulus(const derdec_pkey *const pkey) {
  if (pkey == NULL) {
    return NULL;
  }

  return pkey->modulus.start;
}

size_t derdec_pkey_modulus_size(const derdec_pkey *const pkey) {
  if (pkey == NULL) {
    return 0;
  }

  const uint8_t *const start = pkey->modulus.start;
  const uint8_t *const end = pkey->modulus.end;

  if (start == NULL || end <= start) {
    return 0;
  }

  return (size_t)(end - start);
}

const uint8_t *derdec_pkey_exponent(const derdec_pkey *const pkey) {
  if (pkey == NULL) {
    return NULL;
  }

  return pkey->exponent.start;
}

size_t derdec_pkey_exponent_size(const derdec_pkey *const pkey) {
  if (pkey == NULL) {
    return 0;
  }

  const uint8_t *const start = pkey->exponent.start;
  const uint8_t *const end = pkey->exponent.end;

  if (start == NULL || end <= start) {
    return 0;
  }

  return (size_t)(end - start);
}

bool derdec_pkey_is_pkcs1(const derdec_pkey *const pkey) {
  static const uint8_t pkcs1_id[] = {
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  };

  if (pkey == NULL) {
    return false;
  }

  const uint8_t *const oid_start = pkey->object_id.start;
  const uint8_t *const oid_end = pkey->object_id.end;

  if ((pkey->object_id.type != DERDEC_TLV_OBJECT || oid_start == NULL ||
       oid_end <= oid_start)) {
    return false;
  }

  if ((size_t)(oid_end - oid_start) != sizeof(pkcs1_id)) {
    return false;
  }

  return (memcmp(oid_start, pkcs1_id, sizeof(pkcs1_id)) == 0);
}

derdec_err derdec_decode_pkey(derdec_pkey *result, const uint8_t *data,
                              size_t data_len) {
  if (result == NULL) {
    return DERDEC_MISUSE;
  }

  memset(result, 0, sizeof(*result));

  if (data == NULL || data_len == 0) {
    return DERDEC_MISUSE;
  }

  const uint8_t *data_curr = data;
  const uint8_t *const data_end = (data + data_len);

  // Data must start with a 'SEQUENCE'.
  if (data[0] != 0x30) {
    return DERDEC_PKEY_SIGNATURE;
  }

  derdec_err err;

  /*
  <SEQUENCE>
    <SEQUENCE>
      <OBJECT value="2A 86 48 86 F7 0D 01 01 01" />
      <NULL />
    </SEQUENCE>

    <BITSTRING>
      <SEQUENCE>
        <INTEGER value="00 BE E6 8E E0 B0 8A BA ..." />
        <INTEGER value="01 00 01" />
      </SEQUENCE>
    </BITSTRING>
  </SEQUENCE>
  */

  // Decoding root element (expecting a 'SEQUENCE').
  derdec_tlv root_seq;
  err = derdec_decode_tlv(&root_seq, &data_curr, data_end);
  if (err != DERDEC_OK || root_seq.type != DERDEC_TLV_SEQUENCE) {
    return DERDEC_PKEY_SIGNATURE;
  }

  // Decoding first child element of `root_seq` (expecting a 'SEQUENCE').
  const uint8_t *root_seq_curr = root_seq.start;
  derdec_tlv child_seq;
  err = derdec_decode_tlv(&child_seq, &root_seq_curr, root_seq.end);
  if (err != DERDEC_OK) {
    return DERDEC_PKEY_MALFORMED;
  }

  // Decoding first child element of `child_seq` (expecting an 'OBJECT').
  // This 'OBJECT IDENTIFIER' should denote key format, e.g.:
  // `2A 86 48 86 F7 0D 01 01 01` = `RSA PKCS#1`.
  const uint8_t *child_seq_curr = child_seq.start;
  derdec_tlv child_seq_obj;
  err = derdec_decode_tlv(&child_seq_obj, &child_seq_curr, child_seq.end);
  if (err != DERDEC_OK || child_seq_obj.type != DERDEC_TLV_OBJECT) {
    return DERDEC_PKEY_MALFORMED;
  }

  memcpy(&result->object_id, &child_seq_obj, sizeof(child_seq_obj));

  // Decoding next element after `child_seq` (expecting a 'BITSTRING').
  derdec_tlv child_bitstr;
  err = derdec_decode_tlv(&child_bitstr, &root_seq_curr, root_seq.end);
  if (err != DERDEC_OK || child_bitstr.type != DERDEC_TLV_BITSTRING) {
    return DERDEC_PKEY_MALFORMED;
  }

  // Decoding first child element of `child_bitstr` (expecting a 'SEQUENCE').
  const uint8_t *child_bitstr_curr = child_bitstr.start;
  derdec_tlv child_bitstr_seq;
  err = derdec_decode_tlv(&child_bitstr_seq, &child_bitstr_curr,
                          child_bitstr.end);
  if (err != DERDEC_OK || child_bitstr_seq.type != DERDEC_TLV_SEQUENCE) {
    return DERDEC_PKEY_MALFORMED;
  }

  // Decoding first child element `child_bitstr_seq` (expecting an 'INTEGER').
  // This should constitute the modulus of public key.
  const uint8_t *child_bitstr_seq_curr = child_bitstr_seq.start;
  derdec_tlv child_bitstr_seq_mod;
  err = derdec_decode_tlv(&child_bitstr_seq_mod, &child_bitstr_seq_curr,
                          child_bitstr_seq.end);
  if (err != DERDEC_OK || child_bitstr_seq_mod.type != DERDEC_TLV_INTEGER) {
    return DERDEC_PKEY_MALFORMED;
  }

  size_t mod_len = (child_bitstr_seq_mod.end - child_bitstr_seq_mod.start);
  if (mod_len > 0xff && (mod_len & 0xff) != 0 &&
      child_bitstr_seq_mod.start[0] == 0x00) {
    // If modulus length is not divisible by 256, and the most-significant-byte
    // equals 0x00, then it's a leading zero-byte prefix that we want to omit.

    ++child_bitstr_seq_mod.start;
  }

  memcpy(&result->modulus, &child_bitstr_seq_mod, sizeof(child_bitstr_seq_mod));

  // Decoding second child element `child_bitstr_seq` (expecting an 'INTEGER').
  // This should be the exponent of public key.
  derdec_tlv child_bitstr_seq_exp;
  err = derdec_decode_tlv(&child_bitstr_seq_exp, &child_bitstr_seq_curr,
                          child_bitstr_seq.end);
  if (err != DERDEC_OK || child_bitstr_seq_exp.type != DERDEC_TLV_INTEGER) {
    return DERDEC_PKEY_MALFORMED;
  }

  // NOTE: although according to DER format, the `param` of `child_bitstr`, i.e.
  // the number of unused bits, could be non-zero, we're ignoring it here
  // (assuming that modulus and exponent must be `N * 8` bits).

  memcpy(&result->exponent, &child_bitstr_seq_exp,
         sizeof(child_bitstr_seq_exp));

  return DERDEC_OK;
}

/* -------------------------------------------------- */

// WARNING: this is presumably not cryptographically secure.
derdec_err derdec_pkcs1(uint8_t *buf, size_t buf_len, const uint8_t *plaintext,
                        size_t plaintext_len, uint32_t prng_seed) {
  if (buf == NULL || buf_len == 0) {
    return DERDEC_MISUSE;
  }

  memset(buf, 0, buf_len);

  if (plaintext == NULL || plaintext_len == 0) {
    return DERDEC_MISUSE;
  }

  // Only RSA-2048 (with `uint8_t[256]` buffers) is (currently) supported.
  if (buf_len != 256) {
    return DERDEC_UNSUPPORTED;
  }

  // Message can't be longer than 245 bytes.
  if (plaintext_len > (buf_len - 11)) {
    return DERDEC_MISUSE;
  }

  // Padding length is at least 8 bytes.
  size_t padding_len = (buf_len - plaintext_len - 3);

  uint8_t *buf_curr = buf;

  // Setting the primitive pseudo-random number generator (PRNG).
  //
  // NOTE: loosely based on 'xorshift32'.
  uint32_t prng_value = prng_seed;
  if (prng_value == 0) {
    // If PRNG seed hasn't been provided, we need some (dumb) way to source
    // entropy.
    //
    // TODO(pr3): do this better...

    prng_value = ((uint32_t)plaintext[0] * 90017) + 1534219;
  } else {
    prng_value = (((prng_value + 71339) * 531799) << 3) | 1;
  }

  *buf_curr++ = 0x00;
  *buf_curr++ = 0x02;

  for (size_t i = 0; i < padding_len; ++i) {
    prng_value ^= prng_value << 13;
    prng_value ^= prng_value >> 17;
    prng_value ^= prng_value << 5;

    *buf_curr++ = ((prng_value >> 7) & 0xff) | 1;
  }

  *buf_curr++ = 0x00;

  memcpy(buf_curr, plaintext, plaintext_len);

  return DERDEC_OK;
}

#endif // DERDEC_NO_IMPL

/* ================================================== */
/* ================================================== */
/* ================================================== */

#ifdef __cplusplus
}
#endif

#endif // DERDEC_H
