#ifndef FUZZER_COVERAGE
#define FUZZER_COVERAGE

#include <bitset>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <fstream>

#include <dlfcn.h>

extern "C" {
extern uint32_t __afl_map_size;
}

#define COMMON_FUZZ_COVERAGE_ATTRS __attribute__((no_sanitize("memory")))

COMMON_FUZZ_COVERAGE_ATTRS
inline char * getCoverageMapPtr() {
  // Find the coverage map via dlsym.
  void *f = dlopen(nullptr, RTLD_NOW);
  if (f == nullptr) {
    std::cerr << "Failed to dlopen current process\n";
    std::abort();
  }

  void *obj = dlsym(f, "__afl_area_ptr");
  if (obj == nullptr) {
    std::cerr << "Failed to find __afl_area_ptr\n";
    std::abort();
  }

  // We got a pointer (because dlsym returns pointers) to the coverage map
  // pointer.
  char **ptr = (char **) obj;
  char *map_ptr = *ptr;
  if (map_ptr == nullptr) {
    std::cerr << "coverage map ptr is null?\n";
    std::abort();
  }
  return map_ptr;
}

COMMON_FUZZ_COVERAGE_ATTRS
inline uint32_t getCurrentCoverage() {
  char *map_ptr = getCoverageMapPtr();

  uint32_t result = 0;
  for (uint32_t i = 0; i < __afl_map_size; ++i) {
      if (map_ptr[i])
        ++result;
  }
  return result;
}

COMMON_FUZZ_COVERAGE_ATTRS
inline void completedCycleCallback(uint32_t cycle) {
  if (std::getenv("PRINT_COVERAGE")) {
    std::cout << "COVERAGE: " << cycle << " " << getCurrentCoverage() << "\n";
  }
}

COMMON_FUZZ_COVERAGE_ATTRS
inline void completedSimCallback() {
  if (const char *outpath = std::getenv("PRINT_COVERAGE_MAP")) {
    std::ofstream output(outpath);
    char *map_ptr = getCoverageMapPtr();

    for (uint32_t i = 0; i < __afl_map_size; ++i) {
      output << std::bitset<8>(map_ptr[i]);
    }
  }
}

#undef COMMON_FUZZ_COVERAGE_ATTRS

#endif // FUZZER_COVERAGE
