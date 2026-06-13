#include "crypto_backend.h"
#include <mldsa_native.h>
#include <fips202/fips202.h>
#include <tkey/lib.h>
#include <tkey/debug.h>

int backend_keygen(uint8_t *pubkey, uint8_t *secret_key, const uint32_t *cdi)
{
	MLD_ALIGN uint8_t cdi_buf[32];
	wordcpy(cdi_buf, (const void *)cdi, 8); // copy 8 words (32 bytes)
	MLD_ALIGN uint8_t seeds[64];
	mldsa_shake256(seeds, 64, cdi_buf, 32);
	secure_wipe(cdi_buf, 32);
	int keypair_res = mldsa_keypair_internal(pubkey, secret_key, seeds);
	secure_wipe(seeds, 64);
	if (keypair_res != 0) {
		debug_puts("Key generation failed!\n");
		return -1;
	}
	return 0;
}

int backend_sign(uint8_t *signature, const uint8_t *secret_key, const uint8_t *message, size_t message_size)
{
	MLD_ALIGN uint8_t pre[2 + 255];
	size_t pre_len = mldsa_prepare_domain_separation_prefix(pre, NULL, 0, NULL, 0, MLD_PREHASH_NONE);
	if (pre_len == 0) {
		debug_puts("prepare prefix failed\n");
		return -1;
	}

	MLD_ALIGN uint8_t rnd[32] = {0};
	size_t siglen = 0;
	int res = mldsa_signature_internal(signature, &siglen, message,
					   message_size, pre, pre_len, rnd,
					   secret_key, 0);

	if (res != 0) {
		debug_puts("mldsa_signature_internal failed\n");
		return -1;
	}
	return 0;
}
