#include "hashchain.h"

void hc_init(hashchain_t *hc) { hc->h = HC_FNV_OFFSET_BASIS; }

/* Fold the 8 little-endian bytes of node_id into the accumulator (FNV-1a). */
void hc_fold(hashchain_t *hc, uint64_t node_id) {
  uint64_t h = hc->h;
  for (int i = 0; i < 8; i++) {
    h ^= (node_id >> (8 * i)) & 0xffULL;
    h *= HC_FNV_PRIME;
  }
  hc->h = h;
}

uint64_t hc_value(const hashchain_t *hc) { return hc->h; }
