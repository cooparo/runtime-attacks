#include "cfg.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint64_t src;
  uint64_t dst;
} edge_t;

struct cfg {
  uint64_t text_start;
  uint64_t text_end;

  uint64_t *bb;       /* sorted basic-block start addresses */
  size_t nbb;

  uint64_t *calltgt;  /* sorted legal call-target addresses */
  size_t ncalltgt;

  edge_t *edges;      /* sorted by (src, dst) */
  size_t nedges;
};

/* --- small growable-array helper ----------------------------------------- */

typedef struct {
  void *data;
  size_t elem;
  size_t len;
  size_t cap;
} vec_t;

static void vec_init(vec_t *v, size_t elem) {
  v->data = NULL;
  v->elem = elem;
  v->len = 0;
  v->cap = 0;
}

static int vec_push(vec_t *v, const void *e) {
  if (v->len == v->cap) {
    size_t ncap = v->cap ? v->cap * 2 : 64;
    void *nd = realloc(v->data, ncap * v->elem);
    if (!nd)
      return -1;
    v->data = nd;
    v->cap = ncap;
  }
  memcpy((char *)v->data + v->len * v->elem, e, v->elem);
  v->len++;
  return 0;
}

/* --- comparators / lookups ----------------------------------------------- */

static int cmp_u64(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}

static int cmp_edge(const void *a, const void *b) {
  const edge_t *x = a, *y = b;
  if (x->src != y->src)
    return (x->src > y->src) - (x->src < y->src);
  return (x->dst > y->dst) - (x->dst < y->dst);
}

static int in_sorted_u64(const uint64_t *arr, size_t n, uint64_t key) {
  return bsearch(&key, arr, n, sizeof(uint64_t), cmp_u64) != NULL;
}

/* --- public API ---------------------------------------------------------- */

cfg_t *cfg_load(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "[cfg] cannot open %s\n", path);
    return NULL;
  }

  cfg_t *cfg = calloc(1, sizeof(*cfg));
  if (!cfg) {
    fclose(f);
    return NULL;
  }

  vec_t bb, ct, ed;
  vec_init(&bb, sizeof(uint64_t));
  vec_init(&ct, sizeof(uint64_t));
  vec_init(&ed, sizeof(edge_t));

  int have_text = 0;
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    char *p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    if (*p == '#' || *p == '\n' || *p == '\0')
      continue;

    uint64_t a, b;
    if (sscanf(p, "TEXT %lx %lx", &a, &b) == 2) {
      cfg->text_start = a;
      cfg->text_end = b;
      have_text = 1;
    } else if (sscanf(p, "BB %lx", &a) == 1) {
      vec_push(&bb, &a);
    } else if (sscanf(p, "CALLTGT %lx", &a) == 1) {
      vec_push(&ct, &a);
    } else if (sscanf(p, "EDGE %lx %lx", &a, &b) == 2) {
      edge_t e = {a, b};
      vec_push(&ed, &e);
    }
    /* FUNC lines (and anything unrecognized) are informational — ignore. */
  }
  fclose(f);

  if (!have_text) {
    fprintf(stderr, "[cfg] %s: missing TEXT line\n", path);
    free(bb.data);
    free(ct.data);
    free(ed.data);
    free(cfg);
    return NULL;
  }

  cfg->bb = bb.data;
  cfg->nbb = bb.len;
  cfg->calltgt = ct.data;
  cfg->ncalltgt = ct.len;
  cfg->edges = ed.data;
  cfg->nedges = ed.len;

  qsort(cfg->bb, cfg->nbb, sizeof(uint64_t), cmp_u64);
  qsort(cfg->calltgt, cfg->ncalltgt, sizeof(uint64_t), cmp_u64);
  qsort(cfg->edges, cfg->nedges, sizeof(edge_t), cmp_edge);

  fprintf(stderr,
          "[cfg] loaded %s: text=[0x%lx,0x%lx) bbs=%zu calltgts=%zu edges=%zu\n",
          path, cfg->text_start, cfg->text_end, cfg->nbb, cfg->ncalltgt,
          cfg->nedges);
  return cfg;
}

void cfg_free(cfg_t *cfg) {
  if (!cfg)
    return;
  free(cfg->bb);
  free(cfg->calltgt);
  free(cfg->edges);
  free(cfg);
}

int cfg_in_text(const cfg_t *cfg, uint64_t addr) {
  return addr >= cfg->text_start && addr < cfg->text_end;
}

int cfg_is_bb_start(const cfg_t *cfg, uint64_t addr) {
  return in_sorted_u64(cfg->bb, cfg->nbb, addr);
}

int cfg_is_call_target(const cfg_t *cfg, uint64_t addr) {
  return in_sorted_u64(cfg->calltgt, cfg->ncalltgt, addr);
}

int cfg_has_edge(const cfg_t *cfg, uint64_t src, uint64_t dst) {
  edge_t key = {src, dst};
  return bsearch(&key, cfg->edges, cfg->nedges, sizeof(edge_t), cmp_edge) !=
         NULL;
}
