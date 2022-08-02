# `derdec.h`
🔑 A *silly* single-header library for extracting (decoding) modulus *N* & exponent *E* arbitrary-precision integers from **ASN.1 DER-encoded RSA public keys**.

Includes an example (`examples/encrypt_with_bear.c`) of decoding a public 2048-bit RSA key with `derdec` & encrypting plaintext using a third-party [BearSSL](https://bearssl.org/) library.

Originally created for simple embedded applications (e.g., *ESP8266*). Written in C – zero-allocation & fail-safe.

> ⚠️ Please note: this library has not been tested thoroughly and ~~*may* be~~ should be considered unsafe in real-world applications.

## Usage
```c
#include <derdec.h>
```
In order to use `derdec.h` (see `include/`), it can simply be copied to your project directory.

Alternatively (or preferably), path to `include/` can be added as an include directory (e.g., `-I../deps/derdec/include`) in your *Makefile*/build/compiler setup.

## API
> ✏️ Note: this section is a work-in-progress. For more detailed documentation, see `derdec.h`.

```c
/**
 * Possible (recognized) types of DER TLV's.
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
 */
typedef struct derdec_tlv {
  derdec_tlv_type type;
  uint32_t param;

  const uint8_t *start;
  const uint8_t *end;
} derdec_tlv;

/**
 * Representation of a parsed public key.
 */
typedef struct derdec_pkey {
  derdec_tlv object_id;
  derdec_tlv modulus;
  derdec_tlv exponent;
} derdec_pkey;

/* ======================================== */
/* ======================================== */
/* ======================================== */

/**
 * Returns a string representation for the given TLV `type`.
 */
const char *derdec_tlv_type_str(enum derdec_tlv_type type);

/**
 * Decodes a range of bytes, `[*data_curr, data_end)`, as an ASN.1 DER-encoded
 * TLV item.
 */
derdec_err derdec_decode_tlv(derdec_tlv *result, const uint8_t **data_curr, const uint8_t *data_end);

/**
 * Returns a pointer to (raw bytes of) the modulus of public key `pkey`, or NULL
 * if `pkey` is invalid.
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
 */
bool derdec_pkey_is_pkcs1(const derdec_pkey *const pkey);

/**
 * Decodes a stream of bytes, `data`, of length `data_len`, as an ASR.1
 * DER-encoded RSA public key.
 */
derdec_err derdec_decode_pkey(derdec_pkey *result, const uint8_t *data, size_t data_len);

/**
 * Encodes byte array `plaintext` of length `plaintext_len` as a valid PKCS#1
 * v1.5-padded RSA input, and saves the encoded (not encrypted!) result in
 * buffer `buf` of length `buf_len` (i.e., only so many bytes can be stored in
 * the buffer).
 */
derdec_err derdec_pkcs1(uint8_t *buf, size_t buf_len, const uint8_t *plaintext, size_t plaintext_len, uint32_t prng_seed);
```
