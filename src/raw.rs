// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
   analysis::{
      self,
      SlotView,
   },
   constprop::ConstTracker,
   decode_bundle,
   types::{
      TG_RAW_BASE_SCAN_MAX_BYTES,
      TG_RAW_RUNTIME_ALIAS_BASE,
      TG_RAW_SCORE_MAX_BYTES,
      TG_RAW_SCORE_MIN_BYTES,
      TG_RAW_TILEGX_ACCEPT_SCORE,
      TgConstState,
      TgRawFileVerdict,
   },
};

const RUNTIME_BASE_MIN_HITS: u32 = 2;

struct RawTilegxHeuristic<'bytes> {
   bytes: &'bytes [u8],
}

impl<'bytes> RawTilegxHeuristic<'bytes> {
   const fn new(bytes: &'bytes [u8]) -> Self {
      Self { bytes }
   }

   fn evaluate(self) -> TgRawFileVerdict {
      let sample_len = self.bytes.len().min(TG_RAW_SCORE_MAX_BYTES) & !7_usize;
      if sample_len < TG_RAW_SCORE_MIN_BYTES {
         return TgRawFileVerdict::default();
      }

      let mut total_bundles = 0_u32;
      let mut decoded_bundles = 0_u32;
      for (index, chunk) in self.bytes[..sample_len].chunks_exact(8).enumerate() {
         total_bundles += 1;
         let raw = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
         ]);
         let pc = u64::try_from(index * 8).unwrap_or(u64::MAX);
         if decode_bundle(raw, pc).is_some() {
            decoded_bundles += 1;
         }
      }

      let score = decoded_bundles * 100 / total_bundles;
      TgRawFileVerdict {
         accepted: u8::from(score >= TG_RAW_TILEGX_ACCEPT_SCORE),
         score,
         decoded_bundles,
         total_bundles,
         sampled_bytes: u32::try_from(sample_len).unwrap_or(u32::MAX),
         runtime_base: self.runtime_base(),
         ..TgRawFileVerdict::default()
      }
   }

   fn runtime_base(&self) -> u64 {
      let scan_len = self.bytes.len().min(TG_RAW_BASE_SCAN_MAX_BYTES) & !7_usize;
      if scan_len < TG_RAW_SCORE_MIN_BYTES {
         return 0;
      }

      let mut state = TgConstState::default();
      let mut hits = 0_u32;
      for (index, chunk) in self.bytes[..scan_len].chunks_exact(8).enumerate() {
         let raw = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
         ]);
         let pc = u64::try_from(index * 8).unwrap_or(u64::MAX);
         let Some(bundle) = decode_bundle(raw, pc) else {
            state = TgConstState::default();
            continue;
         };
         let rows = analysis::bundle_code_rows(&bundle);
         for offset in rows.offsets.iter().copied().take(usize::from(rows.n_rows)) {
            let Some(row) = analysis::bundle_row(&bundle, offset) else {
               continue;
            };
            for slot_index in row.slots.iter().copied().take(usize::from(row.n_slots)) {
               let slot = SlotView::new(&bundle.slots[usize::from(slot_index)]);
               let effects = ConstTracker::new(&mut state).analyze_slot(slot);
               if let Some(data_ref) = effects.data_ref
                  && self.alias_target_in_image(data_ref.target)
               {
                  hits += 1;
                  if hits >= RUNTIME_BASE_MIN_HITS {
                     return TG_RAW_RUNTIME_ALIAS_BASE;
                  }
               }
            }
         }
      }
      0
   }

   fn alias_target_in_image(&self, target: u64) -> bool {
      let image_size = u64::try_from(self.bytes.len()).unwrap_or(u64::MAX);
      (TG_RAW_RUNTIME_ALIAS_BASE..TG_RAW_RUNTIME_ALIAS_BASE.saturating_add(image_size))
         .contains(&target)
   }
}

pub fn detect_raw_tilegx(bytes: &[u8]) -> TgRawFileVerdict {
   RawTilegxHeuristic::new(bytes).evaluate()
}

pub fn raw_tilegx_score(bytes: &[u8]) -> u32 {
   detect_raw_tilegx(bytes).score
}
