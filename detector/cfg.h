#ifndef CFG_H
#define CFG_H

#include <stdint.h>

/*
 * Static control-flow graph model, loaded from the flat text file
 * produced by tools/build_cfg.py (see that file for the format).
 *
 * The tracer uses it to validate, online, every taken control-flow
 * transfer inside the victim's .text:
 *   - direct/conditional branches  -> cfg_has_edge(src, dst)
 *   - calls (bl / blr)             -> cfg_is_call_target(dst)
 *   - indirect jumps (br)          -> cfg_is_bb_start(dst) || call target
 *   - returns                      -> shadow call stack (not this module)
 *
 * "Call target" is not "any function entry": it is a function the program
 * calls directly somewhere, or whose address it materialises (coarse-grained
 * forward-edge CFI). See tools/build_cfg.py for how the set is recovered.
 */

typedef struct cfg cfg_t;

/* Parse `path`; returns NULL on failure (and prints a reason to stderr). */
cfg_t *cfg_load(const char *path);
void cfg_free(cfg_t *cfg);

/* [text_start, text_end) of the victim's .text section. */
int cfg_in_text(const cfg_t *cfg, uint64_t addr);

/* Is `addr` the start of a known basic block? */
int cfg_is_bb_start(const cfg_t *cfg, uint64_t addr);

/* Is `addr` a legal call target (a directly-called or address-taken function)? */
int cfg_is_call_target(const cfg_t *cfg, uint64_t addr);

/* Is (src -> dst) a known static edge? `src` is the branch instruction addr. */
int cfg_has_edge(const cfg_t *cfg, uint64_t src, uint64_t dst);

#endif
