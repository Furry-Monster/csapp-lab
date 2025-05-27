#include "cachelab.h"
#include <assert.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * @brief Cache related data structures
 *
 */
typedef struct {
  uint8_t v;      // validator bit for line validation
  uint64_t tag;   // tag for line match
  uint8_t *block; // block for data storage
  uint16_t tt;    // time tick for LRU
} cache_line_struct, *cache_line, **cache_set, ***cache;

static cache cache_ptr;

/**
 * @brief Configuration of the cache simulator
 *
 */
typedef struct {
  int hit, miss, evict;
  int verb;
  // m for machine bit type(32bit or 64bit)
  int m;
  // s for cache set index bitnum,
  // S for cache set size,(how many sets per cache)
  // t for cache line index bitnum,
  // E for cache line size,(how many lines per set)
  // b for cache block index bitnum,
  // B for cache block size,(how many blocks per line)
  int s, S, t, E, b, B;
  char file_path[100];
} cache_config;

cache_config conf;

/*    malloc/free ops      */

/**
 * @brief
 *
 * @return cache
 */
cache cacheMalloc() {
  cache new_cache = (cache)malloc(sizeof(cache_set) * conf.S);
  assert(new_cache != NULL);

  int i;
  for (i = 0; i < conf.S; i++) {
    new_cache[i] = (cache_set)malloc(sizeof(cache_line) * conf.E);
    assert(new_cache[i] != NULL);

    int j;
    for (j = 0; j < conf.E; j++) {
      cache_line line = (cache_line_struct *)malloc(sizeof(cache_line_struct));

      line->v = 0;
      line->tag = 0;
      line->block = (uint8_t *)malloc(sizeof(uint8_t) * conf.B);

      new_cache[i][j] = line;
      assert(new_cache[i][j]);
    }
  }

  printf("successfully allocate cache!\n");
  return new_cache;
}

/**
 * @brief
 *
 * @param cache_to_free
 */
void cacheFree(cache cache_to_free) {
  int i, j;
  assert(cache_to_free);

  for (i = 0; i < conf.S; i++) {
    // if this set is NULL, no need to free
    if (cache_to_free[i] == NULL)
      continue;
    cache_set set_to_free = cache_to_free[i];

    for (j = 0; j < conf.E; j++) {
      // if this line is NULL, no need to free
      if (set_to_free[j] == NULL)
        continue;
      cache_line line_to_free = set_to_free[j];

      if (line_to_free->block != NULL) {
        free(line_to_free->block);
        line_to_free->block = NULL;
      }
      free(line_to_free);
      set_to_free[j] = NULL;
    }
    free(set_to_free);
    cache_to_free[i] = NULL;
  }
  free(cache_to_free);

  printf("successfully free cache!\n");
}

/*    cache ops    */

/**
 * @brief
 *
 * @param block_offset
 */
void blockUpdate(int block_offset) {}

/**
 * @brief
 *
 * @param address
 * @param size
 */
void accessCache(uint64_t address, int size) {
  // parse address
  uint64_t addr_tag = address >> (conf.m - conf.t);
  int addr_set_ind =
      (address >> conf.b) & (((1ULL << 63) - 1) >> (63 - conf.s));
  int addr_block_ind = address & (((1ULL << 63) - 1) >> (63 - conf.b));

  cache_set set = cache_ptr[addr_set_ind];

  int i;
  for (i = 0; i < conf.E; i++) {
    // successfully hit cache
    if (set[i]->v && set[i]->tag == addr_tag) {
      conf.hit++;
      set[i]->tt = 0;
      return;
    }
  }

  // miss cache
  conf.miss++;

  for (i = 0; i < conf.E; i++) {
    if (!set[i]->v) {
      set[i]->v = 1;
      set[i]->tag = addr_tag;
      set[i]->tt = 0;
      blockUpdate(addr_block_ind);
      return;
    }
  }

  // cache is full , we need to replace some line with LRU
  conf.evict++;
  int lru_ind = 0;
  int lru_time = 0;
  for (i = 0; i < conf.E; i++) {
    if (set[i]->tt > lru_time) {
      lru_time = set[i]->tt;
      lru_ind = i;
    }
  }

  set[lru_ind]->v = 1;
  set[lru_ind]->tag = addr_tag;
  set[lru_ind]->tt = 0;
  blockUpdate(addr_block_ind);
}

/*    benchmark     */

/**
 * @brief Benchmark test for cache hit/miss/evict
 *
 * @param cache
 */
void benchmark(cache const cache) {
  printf("Now running benchmark for debug.\n");

  FILE *file = fopen(conf.file_path, "r");
  printf("Load trace file from: %s\n", conf.file_path);
  assert(file);

  char operation; // Symbol for operations ,only L(load data),M(modify
                  // data),S(store data), we won't consider about symbol I(load
                  // instruction)
  uint64_t address; // Address will be depart into 3 part :
                    //  t bit tag + s bit set_ind + b bit block_offset
  int size;         // The number of bytes accessed by the operation
  int i, j;
  while (fscanf(file, " %c %lx,%d", &operation, &address, &size) > 0) {
    switch (operation) {
    case 'L':
      accessCache(address, size);
      break;
    case 'M':
      accessCache(address, size);
      accessCache(address, size);
      break;
    case 'S':
      accessCache(address, size);
      break;
    }

    // LRU update
    for (i = 0; i < conf.S; i++) {
      for (j = 0; j < conf.E; j++) {
        if (cache[i][j]->v)
          cache[i][j]->tt++;
      }
    }
  }

  fclose(file);
}

/*    terminal io   */

/**
 * @brief Print usage of csim to std ostream
 *
 * @param exec
 */
void printUsage(char *exec) {
  printf("Usage: %s [-h] | [-v] -s <num> -E <num> -b <num> -t <filename>\n"
         "Options:\n"
         "\t-h         Print this help message.\n"
         "\t-v         Optional verbose flag.\n"
         "\t-s <num>   Number of set index bits.\n"
         "\t-E <num>   Number of lines per set.\n"
         "\t-b <num>   Number of block offset bits.\n"
         "\t-t <file>  Trace file.\n"
         "Examples:\n"
         "\tlinux> %s -s 4 -E 1 -b 4 -t traces/yi.trace\n"
         "\tlinux> %s -v -s 8 -E 2 -b 4 -t traces/yi.trace\n",
         exec, exec, exec);
}

/**
 * @brief Load cache_config from terminal parameters
 *
 * @param argc
 * @param argv
 * @param conf In type <cache_config>
 */
void loadCacheConfig(int argc, char **argv) {
  conf.hit = 0;
  conf.miss = 0;
  conf.evict = 0;

  // sentence below will return 32bit or 64bit
  // conf.m = sizeof(void *) * 8;
  // default value set to 64bit:
  conf.m = 64;

  int opt;
  while ((opt = getopt(argc, argv, "hvs:E:b:t:")) != -1) {
    switch (opt) {
    case 'h':
      printUsage(argv[0]);
      exit(0);
    case 'v':
      conf.verb = 1;
      break;
    case 's':
      conf.s = atoi(optarg);
      if (conf.s < 0) {
        fprintf(stderr, "Error: Set index bits must be non-negative(>=0).\n");
        exit(1);
      }
      conf.S = 1 << conf.s; // S = 2^s
      break;
    case 'E':
      conf.E = atoi(optarg);
      if (conf.E <= 0) {
        fprintf(stderr, "Error: Lines per set must be positive(>0).\n");
        exit(1);
      }
      break;
    case 'b':
      conf.b = atoi(optarg);
      if (conf.b < 0) {
        fprintf(stderr, "Error: Block bits must be non-negative(>=0).\n");
        exit(1);
      }
      conf.B = 1 << conf.b; // B = 2^b
      break;
    case 't':
      strcpy(conf.file_path, optarg);
      break;
    default:
      fprintf(stderr, "Error: Unexpected exit caused by invalid arguments.\n");
      exit(1);
    }
  }

  conf.t = conf.m - conf.b - conf.s;

  if (conf.s == 0 || conf.E == 0 || conf.b == 0 ||
      strlen(conf.file_path) == 0) {
    fprintf(stderr,
            "Error: Missing required options -s, -E, -b, or -t\n"
            "Usage: %s [-h] | [-v] -s <num> -E <num> -b <num> -t <filename>\n",
            argv[0]);
    exit(1);
  }
}

int main(int argc, char *argv[]) {
  loadCacheConfig(argc, argv);

  cache cache = cacheMalloc();
  cache_ptr = cache;
  benchmark(cache);
  cacheFree(cache);

  printSummary(conf.hit, conf.miss, conf.evict);
  exit(0);
}
