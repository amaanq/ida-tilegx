// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::fmt::{
   self,
   Write,
};

pub fn write_spr_name<W>(out: &mut W, spr: u32) -> fmt::Result
where
   W: Write,
{
   if let Some(name) = spr_alias(spr) {
      out.write_str(name)
   } else {
      write!(out, "spr_{spr:04x}")
   }
}

const fn spr_alias(spr: u32) -> Option<&'static str> {
   Some(match spr {
      0x0780 => "itlb_current_attr",
      0x0781 => "itlb_current_pa",
      0x0782 => "itlb_current_va",
      0x0783 => "itlb_index",
      0x078B => "number_itlb",
      0x1280 => "aar",
      0x2606 => "cache_invalidation_compression_mode",
      0x2607 => "cache_invalidation_mask_0",
      0x2608 => "cache_invalidation_mask_1",
      0x2609 => "cache_invalidation_mask_2",
      0x260A => "cbox_cacheasram_config",
      0x260E => "cbox_mmap_0",
      0x260F => "cbox_mmap_1",
      0x2610 => "cbox_mmap_2",
      0x2611 => "cbox_mmap_3",
      0x2612 => "cbox_msr",
      0x261D => "mem_stripe_config",
      0x2621 => "rshim_coord",
      0x2681 => "i_aar",
      0x270B => "tile_coord",
      0x2781 => "cycle",
      0x2785 => "sim_control",
      0x2805 => "i_asid",
      _ => return None,
   })
}
