use super::{ndks_boot, utils::*};
use crate::{
    config::*,
    structures::{p_region_t, region_t, seL4_SlotPos, seL4_SlotRegion, seL4_UntypedDesc},
};

use crate::{BIT, IS_ALIGNED, MASK};
use log::debug;
use sel4_common::sel4_config::{seL4_MaxUntypedBits, seL4_MinUntypedBits};
use sel4_common::utils::MAX_FREE_INDEX;
use sel4_cspace::interface::*;
use sel4_vspace::*;

pub fn create_untypeds(root_cnode_cap: &cap_t, boot_mem_reuse_reg: region_t) -> bool {
    unsafe {
        let first_untyped_slot = ndks_boot.slot_pos_cur;
        let mut start = 0;
        for i in 0..ndks_boot.resv_count {
            let reg = paddr_to_pptr_reg(&p_region_t {
                start: start,
                end: ndks_boot.reserved[i].start,
            });
            if !create_untypeds_for_region(root_cnode_cap, true, reg.clone(), first_untyped_slot) {
                debug!(
                    "ERROR: creation of untypeds for device region {} at
                       [{}..{}] failed\n",
                    i, reg.start, reg.end
                );
                return false;
            }
            start = ndks_boot.reserved[i].end;
        }

        if start < CONFIG_PADDR_USER_DEVICE_TOP {
            let reg = paddr_to_pptr_reg(&p_region_t {
                start: start,
                end: CONFIG_PADDR_USER_DEVICE_TOP,
            });
            if !create_untypeds_for_region(root_cnode_cap, true, reg.clone(), first_untyped_slot) {
                debug!(
                    "ERROR: creation of untypeds for top device region 
                       [{}..{}] failed\n",
                    reg.start, reg.end
                );
                return false;
            }
        }
        if !create_untypeds_for_region(
            root_cnode_cap,
            false,
            boot_mem_reuse_reg,
            first_untyped_slot,
        ) {
            debug!(
                "ERROR: creation of untypeds for recycled boot memory
                   [{}..{}] failed\n",
                boot_mem_reuse_reg.start, boot_mem_reuse_reg.end
            );
            return false;
        }

        for i in 0..ndks_boot.freemem.len() {
            let reg = ndks_boot.freemem[i];
            ndks_boot.freemem[i] = region_t { start: 0, end: 0 };
            if !create_untypeds_for_region(root_cnode_cap, false, reg, first_untyped_slot) {
                debug!(
                    "ERROR: creation of untypeds for free memory region :{} at
                [{}..{}] failed\n",
                    i, reg.start, reg.end
                );
            }
        }
        (*ndks_boot.bi_frame).untyped = seL4_SlotRegion {
            start: first_untyped_slot,
            end: ndks_boot.slot_pos_cur,
        };
        true
    }
}

fn create_untypeds_for_region(
    root_cnode_cap: &cap_t,
    device_memory: bool,
    mut reg: region_t,
    first_untyped_slot: seL4_SlotPos,
) -> bool {
    // debug!("{:#x} {:#x}", reg.start, reg.end);
    while !is_reg_empty(&reg) {
        let mut size_bits = seL4_WordBits - 1 - (reg.end - reg.start).leading_zeros() as usize;
        if size_bits > seL4_MaxUntypedBits {
            size_bits = seL4_MaxUntypedBits;
        }
        if reg.start != 0 {
            let align_bits = reg.start.trailing_zeros() as usize;
            if size_bits > align_bits {
                size_bits = align_bits;
            }
        }
        if size_bits >= seL4_MinUntypedBits {
            if !provide_untyped_cap(
                root_cnode_cap,
                device_memory,
                reg.start,
                size_bits,
                first_untyped_slot,
            ) {
                return false;
            }
        }
        reg.start += BIT!(size_bits);
        // debug!("start :{:#x} end:{:#x}",reg.start ,reg.end);
    }
    return true;
}

fn provide_untyped_cap(
    root_cnode_cap: &cap_t,
    device_memory: bool,
    pptr: usize,
    size_bits: usize,
    first_untyped_slot: seL4_SlotPos,
) -> bool {
    if size_bits > seL4_MaxUntypedBits || size_bits < seL4_MinUntypedBits {
        debug!("Kernel init: Invalid untyped size {}", size_bits);
        return false;
    }

    if !IS_ALIGNED!(pptr, size_bits) {
        debug!(
            "Kernel init: Unaligned untyped pptr {} (alignment {})",
            pptr, size_bits
        );
        return false;
    }

    if !device_memory && !pptr_in_kernel_window(pptr) {
        debug!(
            "Kernel init: Non-device untyped pptr {} outside kernel window",
            pptr
        );
        return false;
    }

    if !device_memory && !pptr_in_kernel_window(pptr + MASK!(size_bits)) {
        debug!(
            "Kernel init: End of non-device untyped at {} outside kernel window (size {})",
            pptr, size_bits
        );
        return false;
    }
    let ret: bool;
    unsafe {
        let i = ndks_boot.slot_pos_cur - first_untyped_slot;
        if i < CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS {
            (*ndks_boot.bi_frame).untypedList[i] = seL4_UntypedDesc {
                paddr: pptr_to_paddr(pptr),
                sizeBits: size_bits as u8,
                isDevice: device_memory as u8,
                padding: [0; 6],
            };
            let ut_cap = cap_t::new_untyped_cap(
                MAX_FREE_INDEX(size_bits),
                device_memory as usize,
                size_bits,
                pptr,
            );
            ret = provide_cap(root_cnode_cap, ut_cap.clone());
        } else {
            debug!("Kernel init: Too many untyped regions for boot info");
            ret = true
        }
    }
    ret
}
