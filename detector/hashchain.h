#ifndef HASHCHAIN_H
#define HASHCHAIN_H

#include <stdint.h>

/*
 * Cumulative control-flow measurement — a C-FLAT-style hash chain.
 *
 * Every taken control-flow transfer folds its destination address into a
 * running 64-bit accumulator. The final value is a compact fingerprint of
 * the executed path ("attestation token"), emitted at exit.
 *
 * We use a non-cryptographic fold (FNV-1a 64-bit), not BLAKE2/SHA-256:
 * C-FLAT needs an unforgeable digest because it is computed inside a TEE
 * and shipped to a remote verifier; here the tracer is trusted userspace,
 * so a fast fold suffices. Swapping in a real hash later is a one-file
 * change — only hc_fold's body moves.
 */

typedef struct {
  uint64_t h;
} hashchain_t;

#define HC_FNV_OFFSET_BASIS 0xcbf29ce484222325ULL
#define HC_FNV_PRIME 0x100000001b3ULL

void hc_init(hashchain_t *hc);
void hc_fold(hashchain_t *hc, uint64_t node_id);
uint64_t hc_value(const hashchain_t *hc);

#endif
