#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H

#include <stdint.h>
#include <stddef.h>

#if defined(ALGO_MLDSA)
#define BACKEND_SECRET_KEY_SIZE 2560
#define BACKEND_PUBKEY_SIZE 1312
#define BACKEND_SIG_SIZE 2420
#define BACKEND_APP_NAME "mlds"
#elif defined(ALGO_ED25519)
#define BACKEND_SECRET_KEY_SIZE 64
#define BACKEND_PUBKEY_SIZE 32
#define BACKEND_SIG_SIZE 64
#define BACKEND_APP_NAME "sign"
#else
#error "Must define ALGO_MLDSA or ALGO_ED25519"
#endif

/**
 * Generate a keypair from the CDI.
 * Returns 0 on success, non-zero on failure.
 */
int backend_keygen(uint8_t *pubkey, uint8_t *secret_key, const uint32_t *cdi);

/**
 * Sign a message.
 * Returns 0 on success, non-zero on failure.
 */
int backend_sign(uint8_t *signature, const uint8_t *secret_key, const uint8_t *message, size_t message_size);

#endif
