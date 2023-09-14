#include <openssl/crypto.h>

uint32_t FIPS_version(void) {
  return 1;
}

struct CRYPTO_STATIC_MUTEX {

};
void CRYPTO_STATIC_MUTEX_lock_read(struct CRYPTO_STATIC_MUTEX *lock);
void CRYPTO_STATIC_MUTEX_lock_write(struct CRYPTO_STATIC_MUTEX *lock);
void CRYPTO_STATIC_MUTEX_unlock_read(struct CRYPTO_STATIC_MUTEX *lock);
void CRYPTO_STATIC_MUTEX_unlock_write(struct CRYPTO_STATIC_MUTEX *lock);

void CRYPTO_STATIC_MUTEX_lock_read(struct CRYPTO_STATIC_MUTEX *lock) {}

void CRYPTO_STATIC_MUTEX_lock_write(struct CRYPTO_STATIC_MUTEX *lock) {}

void CRYPTO_STATIC_MUTEX_unlock_read(struct CRYPTO_STATIC_MUTEX *lock) {}

void CRYPTO_STATIC_MUTEX_unlock_write(struct CRYPTO_STATIC_MUTEX *lock) {}
