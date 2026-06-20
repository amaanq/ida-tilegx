// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Hex-Rays discovery plugin for TILE-Gx. It does not generate usable
// microcode yet; it proves whether Hex-Rays reaches the microcode filter.

#include <algorithm>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>

#include <diskio.hpp>
#include <hexrays.hpp>

static constexpr int PLFM_TILEGX = 0x8369;

static void probe_log(const char *fmt, ...) {
   char msgbuf[512];
   va_list va;
   va_start(va, fmt);
   int n = qvsnprintf(msgbuf, sizeof(msgbuf), fmt, va);
   va_end(va);
   if (n <= 0) {
      return;
   }
   n = std::min(n, static_cast<int>(sizeof(msgbuf) - 1));

   char path[QMAXPATH];
   qmakepath(path, sizeof(path), get_user_idadir(), "tilegx_hexrays_probe.log", nullptr);
   const int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
   if (fd >= 0) {
      const ssize_t written = write(fd, msgbuf, static_cast<size_t>(n));
      (void)written;
      close(fd);
   }
}

struct tilegx_probe_filter_t : public microcode_filter_t {
   bool match(codegen_t &cdg) override {
      if (PH.id != PLFM_TILEGX) {
         return false;
      }
      probe_log("match ea=%" PRIx64 " itype=%u\n", static_cast<uint64_t>(cdg.insn.ea), cdg.insn.itype);
      return true;
   }

   merror_t apply(codegen_t &cdg) override {
      probe_log("apply ea=%" PRIx64 " itype=%u\n", static_cast<uint64_t>(cdg.insn.ea), cdg.insn.itype);
      return MERR_INSN;
   }
};

struct tilegx_hexrays_probe_t : public plugmod_t {
   tilegx_probe_filter_t filter;
   bool installed = false;

   tilegx_hexrays_probe_t() : installed(install_microcode_filter(&filter, true)) {
      probe_log("init version=%s ph=%d installed=%d\n", get_hexrays_version(), PH.id, installed ? 1 : 0);
   }

   tilegx_hexrays_probe_t(const tilegx_hexrays_probe_t &) = delete;
   tilegx_hexrays_probe_t &operator=(const tilegx_hexrays_probe_t &) = delete;
   tilegx_hexrays_probe_t(tilegx_hexrays_probe_t &&) = delete;
   tilegx_hexrays_probe_t &operator=(tilegx_hexrays_probe_t &&) = delete;

   ~tilegx_hexrays_probe_t() override {
      if (installed) {
         install_microcode_filter(&filter, false);
      }
      probe_log("term ph=%d installed=%d\n", PH.id, installed ? 1 : 0);
      term_hexrays_plugin();
   }

   bool idaapi run(size_t arg) override {
      (void)arg;
      probe_log("run ph=%d installed=%d\n", PH.id, installed ? 1 : 0);
      return false;
   }
};

static plugmod_t *idaapi init() {
   if (!init_hexrays_plugin()) {
      probe_log("no_hexrays ph=%d\n", PH.id);
      return nullptr;
   }
   return new tilegx_hexrays_probe_t;
}

static const char comment[] = "Probe Hex-Rays microcode filter availability for TILE-Gx";

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_HIDE | PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    comment,
    "",
    "TILE-Gx Hex-Rays probe",
    "",
};
