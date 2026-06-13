#include "crypto_backend.h"
#include <monocypher/monocypher-ed25519.h>
#include <tkey/lib.h>

int backend_keygen(uint8_t *pubkey, uint8_t *secret_key, const uint32_t *cdi)
{
	crypto_ed25519_key_pair(secret_key, pubkey, (uint8_t *)cdi);
	return 0;
}

int backend_sign(uint8_t *signature, const uint8_t *secret_key, const uint8_t *message, size_t message_size)
{
	crypto_ed25519_sign(signature, secret_key, message, message_size);
	return 0;
}
