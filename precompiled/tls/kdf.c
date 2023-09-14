#include "../../crypto/fipsmodule/tls/internal.h"
#include <openssl/bytestring.h>
#include <openssl/hkdf.h>
#include <openssl/mem.h>

int CRYPTO_tls13_hkdf_expand_label(uint8_t *out, size_t out_len,
                                   const EVP_MD *digest,  //
                                   const uint8_t *secret, size_t secret_len,
                                   const uint8_t *label, size_t label_len,
                                   const uint8_t *hash, size_t hash_len) {
  static const uint8_t kProtocolLabel[] = "tls13 ";
  CBB cbb, child;
  uint8_t *hkdf_label = NULL;
  size_t hkdf_label_len;

  CBB_zero(&cbb);
  if (!CBB_init(&cbb, 2 + 1 + sizeof(kProtocolLabel) - 1 + label_len + 1 +
                          hash_len) ||
      !CBB_add_u16(&cbb, out_len) ||
      !CBB_add_u8_length_prefixed(&cbb, &child) ||
      !CBB_add_bytes(&child, kProtocolLabel, sizeof(kProtocolLabel) - 1) ||
      !CBB_add_bytes(&child, label, label_len) ||
      !CBB_add_u8_length_prefixed(&cbb, &child) ||
      !CBB_add_bytes(&child, hash, hash_len) ||
      !CBB_finish(&cbb, &hkdf_label, &hkdf_label_len)) {
    CBB_cleanup(&cbb);
    return 0;
  }

  const int ret = HKDF_expand(out, out_len, digest, secret, secret_len,
                              hkdf_label, hkdf_label_len);
  OPENSSL_free(hkdf_label);
  return ret;
}
