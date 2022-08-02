#include <bearssl.h>
#include <derdec.h>
//
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// clang-format off
/**
 * @file encrypt_with_bear.c
 * @brief A handy wrapper for the low-level BearSSL RSA encryption API.
 *
 * On success, returns 0.
 * On failure, returns a non-zero value (e.g., -1).
 *
 * === Usage ===
 *
 * ```c
 *
 * int main(void) {
 *   derdec_pkey pkey;
 *
 *   // derdec_decode_pkey(&pkey, ...);
 *   // ...
 *
 *   const char *plaintext = "hello world";
 *   uint8_t buf[256];
 *
 *   if (encrypt_with_bear(
 *         buf,
 *         sizeof(buf),
 *         plaintext,
 *         strlen(plaintext),
 *         &pkey) != 0) {
 *     fprintf(stderr, "[!] encrypt_with_bear failed\n");
 *
 *     return 1;
 *   }
 *
 *   for (size_t i = 0; i < sizeof(buf); ++i) {
 *     printf("%02x", buf[i]);
 *   }
 *   printf("\n");
 *
 *   return 0;
 * }
 *
 * ```
 *
 */
// clang-format on

/* (RSA-2048)

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA04q+ItIxPN3Q45rCtmOJ
/tyDA3b6+WUSR1rMxNCPVJrFCw6EpRGcWZ9fzYEisihXrkgLuY1OepZ6IW29I6Kq
/EU4NqAfdrbDIj5LslTBMvyF4N8CKfvtmvwNvhzZKpwQoy/UFIlLIQDM6oGQ9tFp
zJhnXhw/oVb7aJT0p6ZwJqx3aRpgvLm/+O5QU6SVLsfRDduu3ovx7Mm1Nfw5Djou
OTQVlwmlKr5bYQfgfCttRHygRG6utm828uwhStXhAeOJ/sOL6wHnlJYKxQGWn57j
KnTIgA3FCKSpF+Te+14lJ8JDRNRAQjeRgAI0T0/6S+z7mqw2tUIJzRZoRBM31jaA
IwIDAQAB
-----END PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA04q+ItIxPN3Q45rCtmOJ/tyDA3b6+WUSR1rMxNCPVJrFCw6E
pRGcWZ9fzYEisihXrkgLuY1OepZ6IW29I6Kq/EU4NqAfdrbDIj5LslTBMvyF4N8C
KfvtmvwNvhzZKpwQoy/UFIlLIQDM6oGQ9tFpzJhnXhw/oVb7aJT0p6ZwJqx3aRpg
vLm/+O5QU6SVLsfRDduu3ovx7Mm1Nfw5DjouOTQVlwmlKr5bYQfgfCttRHygRG6u
tm828uwhStXhAeOJ/sOL6wHnlJYKxQGWn57jKnTIgA3FCKSpF+Te+14lJ8JDRNRA
QjeRgAI0T0/6S+z7mqw2tUIJzRZoRBM31jaAIwIDAQABAoIBABvjbq2oiFU96QwY
mxLwjIDNEXijdvLqID7H+bb4x+yfetq6T0Jzz+kA2eB95dUW/Hg9h04vEumWbQN7
NDQ+fcxEU+Tft0YvUgpxrAkWo2HVaND8lYxzah/Emws1QmwbpxXceFk8wGrZcCp6
amIfuZL/hKEjmD/s97gR6y8vAhoW5TPU+6rxjFvL6L0bmXKFJjDZIwi9ZqW8snGz
CEsBQEnqqXCveK5dpRcL6ZSglD+nCQtm11qr1V9MBXaFR99XuMZVMH2s1Y/MFqVw
YsIyLzXilyyG8C5TNvFNFGp4bamQKrgug7f3GUOY5ICvMDPH7y9QYRdKwobBvzE7
4uJHhgECgYEA9b9lf4sDIADMqqRBBTJ0Ni0oaFq/fO3/1AM7NnKBeUWDanPtGciR
jeinj9e9FP8mfk99l5bwF5mXZBVSpjY+1coBRoHay+pbfYYz6M9adfxXkc9s2n2L
s9esECl7ta5ANt3mGiEzCp8++rKITzZGCvDcuUSKEuTm2D+smBW9qA0CgYEA3F4G
6MgTzRXAzT17i8ZS33DWt0ny4AsD8slY5FNhJICjxOAAxUjclOqZL3DuFPIKBeoK
m9Gnat76hiQgq3z1h7Nln9/AI1mWVMkGUzBbnUvta1acReI5/LPG3FgkFzzkDg0O
gehISHUVeVQjI2lSd49GeHjmm12hKgDBDNfeDO8CgYB8DZk0ED2Mmzq17WKxN+34
J0WdoCnH6/DX2qW6b4UybcfQJiMLf/cSFt73OuXFQqPw4Tm6G0Sp9Su6JxVouDtx
+p44NHb5tx1mOSfdH0dABhlCjt4ZUYUDTR0br4U2inb5+3wbtqSoeQj2zscGjZRA
E6SolZPJw+lQQpxizZ7GxQKBgDzeI95sVTvShFysXNGwx/c7vbMG0/UaVc7b2pfG
iBCDD7kzfkL/6x2e5wz5jmluqWIU0TVU5X9Zc61VkUiMzWzcGnfcX7/j4OguVnbn
5oY+EKgTVjrfT9EC/yyhk+ZvRTa0WIt9U2ngHTxUBxii4MpxYq+oBVpotDlb1/bq
MUU1AoGBAKprlhL97NL2uxlI+4WGdpfH43yaVGzM5ETgfTdb0GjsXqljjU5QAnOA
JrLFuJh/nWMwiIqV0hbx84+Epg/xTNDlbj7P43X07/pp+IqqU0gtQsdcNYL4YHvl
Pk5IHEM1Jh03cK96Oq2OIEWBrCPGdTVe6LcEveTmdUVXTSiFQDUo
-----END RSA PRIVATE KEY-----

*/
static const uint8_t raw_pkey[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd3, 0x8a, 0xbe,
    0x22, 0xd2, 0x31, 0x3c, 0xdd, 0xd0, 0xe3, 0x9a, 0xc2, 0xb6, 0x63, 0x89,
    0xfe, 0xdc, 0x83, 0x03, 0x76, 0xfa, 0xf9, 0x65, 0x12, 0x47, 0x5a, 0xcc,
    0xc4, 0xd0, 0x8f, 0x54, 0x9a, 0xc5, 0x0b, 0x0e, 0x84, 0xa5, 0x11, 0x9c,
    0x59, 0x9f, 0x5f, 0xcd, 0x81, 0x22, 0xb2, 0x28, 0x57, 0xae, 0x48, 0x0b,
    0xb9, 0x8d, 0x4e, 0x7a, 0x96, 0x7a, 0x21, 0x6d, 0xbd, 0x23, 0xa2, 0xaa,
    0xfc, 0x45, 0x38, 0x36, 0xa0, 0x1f, 0x76, 0xb6, 0xc3, 0x22, 0x3e, 0x4b,
    0xb2, 0x54, 0xc1, 0x32, 0xfc, 0x85, 0xe0, 0xdf, 0x02, 0x29, 0xfb, 0xed,
    0x9a, 0xfc, 0x0d, 0xbe, 0x1c, 0xd9, 0x2a, 0x9c, 0x10, 0xa3, 0x2f, 0xd4,
    0x14, 0x89, 0x4b, 0x21, 0x00, 0xcc, 0xea, 0x81, 0x90, 0xf6, 0xd1, 0x69,
    0xcc, 0x98, 0x67, 0x5e, 0x1c, 0x3f, 0xa1, 0x56, 0xfb, 0x68, 0x94, 0xf4,
    0xa7, 0xa6, 0x70, 0x26, 0xac, 0x77, 0x69, 0x1a, 0x60, 0xbc, 0xb9, 0xbf,
    0xf8, 0xee, 0x50, 0x53, 0xa4, 0x95, 0x2e, 0xc7, 0xd1, 0x0d, 0xdb, 0xae,
    0xde, 0x8b, 0xf1, 0xec, 0xc9, 0xb5, 0x35, 0xfc, 0x39, 0x0e, 0x3a, 0x2e,
    0x39, 0x34, 0x15, 0x97, 0x09, 0xa5, 0x2a, 0xbe, 0x5b, 0x61, 0x07, 0xe0,
    0x7c, 0x2b, 0x6d, 0x44, 0x7c, 0xa0, 0x44, 0x6e, 0xae, 0xb6, 0x6f, 0x36,
    0xf2, 0xec, 0x21, 0x4a, 0xd5, 0xe1, 0x01, 0xe3, 0x89, 0xfe, 0xc3, 0x8b,
    0xeb, 0x01, 0xe7, 0x94, 0x96, 0x0a, 0xc5, 0x01, 0x96, 0x9f, 0x9e, 0xe3,
    0x2a, 0x74, 0xc8, 0x80, 0x0d, 0xc5, 0x08, 0xa4, 0xa9, 0x17, 0xe4, 0xde,
    0xfb, 0x5e, 0x25, 0x27, 0xc2, 0x43, 0x44, 0xd4, 0x40, 0x42, 0x37, 0x91,
    0x80, 0x02, 0x34, 0x4f, 0x4f, 0xfa, 0x4b, 0xec, 0xfb, 0x9a, 0xac, 0x36,
    0xb5, 0x42, 0x09, 0xcd, 0x16, 0x68, 0x44, 0x13, 0x37, 0xd6, 0x36, 0x80,
    0x23, 0x02, 0x03, 0x01, 0x00, 0x01,
};
static const size_t raw_pkey_len = sizeof(raw_pkey);

// --------------------------------------------------

int encrypt_with_bear(uint8_t *buf, size_t buf_len, const char *const plaintext,
                      size_t plaintext_len, const derdec_pkey *const pkey) {
  if (buf == NULL || buf_len != 256 || plaintext == NULL ||
      plaintext_len == 0 || pkey == NULL) {
    // ERROR: invalid arguments.

    return -1;
  }

  memset(buf, 0, buf_len);

  if (plaintext_len > 245) {
    // ERROR: plaintext is too long.

    return -2;
  }

  if ((pkey->modulus.start == NULL || pkey->modulus.end == NULL) ||
      (pkey->exponent.start == NULL || pkey->exponent.end == NULL)) {
    // ERROR: invalid public key given.

    return -3;
  }

  if (derdec_pkcs1(buf, buf_len, (const uint8_t *)plaintext, plaintext_len,
                   0) != DERDEC_OK) {
    // ERROR: PKCS#1 encoder has failed.

    return -4;
  }

  const br_rsa_public_key pkey_bear = {
      (unsigned char *)derdec_pkey_modulus(pkey),
      derdec_pkey_modulus_size(pkey),
      (unsigned char *)derdec_pkey_exponent(pkey),
      derdec_pkey_exponent_size(pkey),
  };

  br_rsa_public rsa_pub_engine = br_rsa_public_get_default();

  if (!rsa_pub_engine(buf, buf_len, &pkey_bear)) {
    // ERROR: BearSSL's RSA-2048 encryption engine has failed.

    return -5;
  }

  // OK: plaintext has been encrypted successfully. Result was saved into `buf`.

  return 0;
}

// --------------------------------------------------

int main(void) {
  derdec_pkey pkey;

  derdec_err err;
  if ((err = derdec_decode_pkey(&pkey, raw_pkey, raw_pkey_len)) != DERDEC_OK) {
    fprintf(stderr, "[!] derdec_decode_pkey failed: %s\n", derdec_err_str(err));

    return 1;
  }

  if (!derdec_pkey_is_pkcs1(&pkey)) {
    fprintf(stderr, "[!] pkey is not a PKCS1 public key\n");

    return 2;
  }

  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // The plaintext to be encrypted.
  //
  const char *plaintext = "hello world";
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  uint8_t buf[256];
  if (encrypt_with_bear(buf, sizeof(buf), plaintext, strlen(plaintext),
                        &pkey) != 0) {
    fprintf(stderr, "[!] encrypt_with_bear failed\n");

    return 3;
  }

  for (size_t i = 0; i < sizeof(buf); ++i) {
    printf("%02x", buf[i]);
  }
  printf("\n");

  return 0;
}
