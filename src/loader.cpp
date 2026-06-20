// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Loader for raw little-endian TILE-Gx firmware blobs.

#include <cstddef>
#include <cstdint>

#include <auto.hpp>
#include <diskio.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <segregs.hpp>

#include "ffi.hpp"

static constexpr const char *PROCESSOR_NAME = "tilegx";
static constexpr const char *FORMAT_NAME = "TILE-Gx firmware/flat binary";
static constexpr size_t MAX_SAMPLE_SIZE = size_t{256} * 1024;

class RawTilegxDetector final {
 public:
   explicit RawTilegxDetector(linput_t &input) : input_(&input), file_size_(qlsize(&input)) {}

   [[nodiscard]] TgRawFileVerdict evaluate() const {
      if (!can_sample()) {
         return {};
      }

      const qoff64_t old_pos = qltell(input_);
      uint8_t sample[MAX_SAMPLE_SIZE];
      qlseek(input_, 0, SEEK_SET);
      const ssize_t got = qlread(input_, sample, sample_size());
      qlseek(input_, old_pos, SEEK_SET);
      if (got <= 0) {
         return {};
      }
      return tg_detect_raw_tilegx(sample, static_cast<size_t>(got));
   }

 private:
   [[nodiscard]] bool can_sample() const { return file_size_ >= 64 && (file_size_ & 7) == 0; }

   [[nodiscard]] size_t sample_size() const {
      const auto max_sample = static_cast<int64>(MAX_SAMPLE_SIZE);
      return static_cast<size_t>(file_size_ < max_sample ? file_size_ : max_sample);
   }

   linput_t *input_;
   int64 file_size_;
};

static int idaapi accept_file(qstring *fileformatname, qstring *processor, linput_t *li, const char *filename) {
   (void)filename;
   if (fileformatname == nullptr || processor == nullptr || li == nullptr) {
      return 0;
   }
   if (!tg_abi_layout_matches()) {
      msg("TILE-Gx raw loader: Rust/C++ ABI layout mismatch\n");
      return 0;
   }
   if (RawTilegxDetector(*li).evaluate().accepted == 0) {
      return 0;
   }
   *fileformatname = FORMAT_NAME;
   *processor = PROCESSOR_NAME;
   return ACCEPT_FIRST | 1;
}

static void idaapi load_file(linput_t *li, ushort neflags, const char *fileformatname) {
   (void)neflags;
   if (!tg_abi_layout_matches()) {
      loader_failure("TILE-Gx raw loader Rust/C++ ABI layout mismatch");
   }
   const int64 file_size = qlsize(li);
   if (file_size <= 0) {
      loader_failure("Invalid TILE-Gx raw binary size");
   }
   const TgRawFileVerdict verdict = RawTilegxDetector(*li).evaluate();
   if (verdict.accepted == 0) {
      loader_failure("Input no longer matches the TILE-Gx raw binary heuristic");
   }
   if (!set_processor_type(PROCESSOR_NAME, SETPROC_LOADER)) {
      loader_failure("Could not select TILE-Gx processor module");
   }

   if (verdict.runtime_base > static_cast<uint64_t>(BADADDR) - static_cast<uint64_t>(file_size)) {
      loader_failure("TILE-Gx raw binary does not fit at inferred runtime base");
   }
   const ea_t start = static_cast<ea_t>(verdict.runtime_base);
   const ea_t end = start + static_cast<ea_t>(file_size);
   const sel_t selector = setup_selector(0);
   if (!add_segm(selector, start, end, "ROM", "ROM")) {
      loader_failure("Could not create ROM segment");
   }

   segment_t *seg = getseg(start);
   if (seg != nullptr) {
      seg->type = SEG_NORM;
      seg->perm = SEGPERM_READ | SEGPERM_EXEC;
      set_segm_addressing(seg, 2);
      update_segm(seg);
   }

   qlseek(li, 0, SEEK_SET);
   if (file2base(li, 0, start, end, FILEREG_PATCHABLE) == 0) {
      loader_failure("Could not load TILE-Gx raw binary bytes");
   }

   set_default_dataseg(selector);
   set_imagebase(start);
   set_loader_format_name(fileformatname != nullptr ? fileformatname : FORMAT_NAME);
   inf_set_filetype(f_BIN);
   inf_set_app_bitness(64);
   inf_set_start_ea(start);
   inf_set_start_cs(selector);
   inf_set_start_ip(start);
   inf_set_min_ea(start);
   inf_set_max_ea(end);
   auto_make_code(start);
}

loader_t LDSC = {
    IDP_INTERFACE_VERSION, 0, accept_file, load_file, nullptr, nullptr, nullptr,
};
