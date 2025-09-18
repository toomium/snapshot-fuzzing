/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "config.h"

#define _GNU_SOURCE
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include "nyx.h"
#include "crash_handler.h"
#include "fuzz.h"
#include "stats.h"
#include "afl_runtime.h"

/*
 * This file defines a set of APIs exposed to mozilla-central
 * for the purpose of implementing the NYX interface in our
 * codebase. Any changes or extensions to this interface must
 * be reflected in tools/fuzzing/nyx/ in mozilla-central as well.
 */

// External function to configure agent capabilities
void capabilites_configuration(bool timeout_detection, bool agent_tracing,
                               bool ijon_tracing);

// This is the per-iteration trace buffer used by AFL for coverage
extern unsigned char* trace_buffer;

// External reference to the buffer holding all PCs (from pc-table)
extern void* pcmap_buffer;
extern size_t pcmap_buffer_size;

// Used to suppress output with MOZ_FUZZ_NYX_QUIET
static bool nyx_quiet = false;

// Used by prctl interceptor
bool nyx_started = false;

void check_host_config(host_config_t host_config) {
  if (host_config.host_magic != NYX_HOST_MAGIC) {
    hprintf(
        "Error: NYX_HOST_MAGIC not found in host configuration - You are "
        "probably using an outdated version of QEMU-Nyx...");
    kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
  }

  if (host_config.host_version != NYX_HOST_VERSION) {
    hprintf(
        "Error: NYX_HOST_VERSION not found in host configuration - You are "
        "probably using an outdated version of QEMU-Nyx...");
    kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
  }

  hprintf("[*] %s: host_config.bitmap_size: 0x%x\n", __func__,
          host_config.bitmap_size);
  hprintf("[*] %s: host_config.ijon_bitmap_size: 0x%x\n", __func__,
          host_config.ijon_bitmap_size);
  hprintf("[*] %s: host_config.payload_buffer_size: 0x%x\n", __func__,
          host_config.payload_buffer_size);
}

void nyx_start(void) {
  // Stats use a persistent page, we need to make sure to initialize this
  // late enough so the process won't fork/exit afterwards.
  init_stats();

  host_config_t host_config;
  kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
  check_host_config(host_config);

  capabilites_configuration(false, true, true);
  nyx_quiet = !!getenv("MOZ_FUZZ_NYX_QUIET");

  init_crash_handling();

  if (!!getenv("MOZ_FUZZ_COVERAGE")) {
    // Write module info, this is the mapping of modules into address space
    char* modinfo = get_afl_modinfo_string();
    if (modinfo) {
      upload_file_to_host(modinfo, strlen(modinfo), "modinfo.txt");
    }

    // Write PC table, this is the mapping of coverage map index to PC
    upload_file_to_host(pcmap_buffer, pcmap_buffer_size, "pcmap.dump");
  }

  nyx_init_start();
  nyx_started = true;
}

uint32_t nyx_get_owned_raw_fuzz_data(void** data) {
  return internal_get_owned_raw_fuzz_data(data);
}

uint32_t nyx_get_raw_fuzz_data(void* data, uint32_t len) {
  return internal_get_raw_fuzz_data(data, len);
}

uint32_t nyx_get_next_fuzz_data(void* data, uint32_t len) {
  return internal_get_next_fuzz_data(data, len);
}

uint32_t nyx_get_protobuf_fuzz_data(void* data, uint32_t len, uint32_t msg_type) {
  return internal_get_protobuf_fuzz_data(data, len, msg_type);
}

void nyx_release(uint32_t iterations) {
  on_iteration(iterations);
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
}

void nyx_handle_event(const char* type, const char* file, int line,
                      const char* reason) {
  if (!strcmp(type, "MOZ_CRASH")) {
    on_moz_crash();
    firefox_handler_MOZ_CRASH(file, line);
  } else if (!strcmp(type, "MOZ_ASSERT")) {
    on_moz_assert();
    firefox_handler_MOZ_ASSERT(file, line, reason);
  } else if (!strcmp(type, "MOZ_RELEASE_ASSERT")) {
    on_moz_release_assert();
    firefox_handler_MOZ_RELEASE_ASSERT(file, line, reason);
  } else if (!strcmp(type, "MOZ_DIAGNOSTIC_ASSERT")) {
    on_moz_diagnostic_assert();
    firefox_handler_MOZ_DIAGNOSTIC_ASSERT(file, line, reason);
  } else if (!strcmp(type, "MOZ_IPC_DROP_PEER")) {
    on_drop_peer();
  } else if (!strcmp(type, "MOZ_IPC_UNKNOWN_TYPE")) {
    on_msgtype_unknown();
  } else if (!strcmp(type, "MOZ_IPC_DESERIALIZE_ERROR")) {
    on_msg_deserialize_error();
  } else if (!strcmp(type, "MOZ_IPC_PROCESS_ERROR")) {
    on_msg_process_error();
  } else if (!strcmp(type, "MOZ_IPC_ROUTE_ERROR")) {
    on_msg_route_error();
  } else if (!strcmp(type, "MOZ_IPC_NOTALLOWED_ERROR")) {
    on_msg_notallowed_error();
  } else if (!strcmp(type, "MOZ_TIMEOUT")) {
    on_timeout();
  } else {
#ifdef DEBUG
    __assert(__func__, __FILE__, __LINE__, "Unknown event type");
#else
    hprintf("Unknown event type: %s\n", type);
#endif
  }
}

void nyx_puts(const char* msgbuf) {
  if (!nyx_quiet) {
    hprintf("%s", msgbuf);
  }
}

void nyx_dump_file(void* buffer, size_t len, const char* filename) {
  upload_file_to_host(buffer, len, filename);
}
