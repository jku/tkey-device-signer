#ifndef MLDSA_CONFIG_H
#define MLDSA_CONFIG_H

#ifndef MLD_INLINE
#define MLD_INLINE inline
#endif

#define MLD_CONFIG_PARAMETER_SET 44
#define MLD_CONFIG_NAMESPACE_PREFIX mldsa
#define MLD_CONFIG_REDUCE_RAM
#define MLD_CONFIG_NO_RANDOMIZED_API
#define MLD_CONFIG_NO_SUPERCOP
#define MLD_CONFIG_NO_ASM

#define MLD_CONFIG_CUSTOM_ZEROIZE
#define MLD_CONFIG_CUSTOM_MEMCPY
#define MLD_CONFIG_CUSTOM_MEMSET

#include <tkey/lib.h>

static MLD_INLINE void mld_zeroize(void *ptr, size_t len) {
    secure_wipe(ptr, len);
}

static MLD_INLINE void *mld_memcpy(void *dest, const void *src, size_t n) {
    return memcpy(dest, src, (unsigned)n);
}

static MLD_INLINE void *mld_memset(void *s, int c, size_t n) {
    return memset(s, c, (unsigned)n);
}

#endif /* MLDSA_CONFIG_H */
