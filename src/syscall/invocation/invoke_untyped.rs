use crate::ffi::tcbDebugAppend;
use crate::syscall::{
    FREE_INDEX_TO_OFFSET, GET_FREE_INDEX, GET_OFFSET_FREE_PTR, OFFSET_TO_FREE_IDNEX,
};
use sel4_common::{
    object::ObjectType, sel4_config::*, structures::exception_t, utils::convert_to_mut_type_ref,
    BIT, ROUND_DOWN,
};
use sel4_cspace::interface::{cap_t, cte_t, insert_new_cap};
use sel4_task::{get_current_domain, tcb_t};
use sel4_vspace::{pptr_t, VMReadWrite};

use crate::utils::*;

fn create_new_objects(
    obj_type: ObjectType,
    parent: &mut cte_t,
    dest_cnode: &mut cte_t,
    dest_offset: usize,
    dest_length: usize,
    region_base: usize,
    user_size: usize,
    device_mem: usize,
) {
    // debug!("create_new_object: {:?}", obj_type);
    let object_size = obj_type.get_object_size(user_size);
    for i in 0..dest_length {
        let cap = create_object(
            obj_type,
            region_base + (i << object_size),
            user_size,
            device_mem,
        );
        insert_new_cap(parent, dest_cnode.get_offset_slot(dest_offset + i), &cap);
    }
}

fn create_object(
    obj_type: ObjectType,
    region_base: pptr_t,
    user_size: usize,
    device_mem: usize,
) -> cap_t {
    match obj_type {
        ObjectType::TCBObject => {
            let tcb = convert_to_mut_type_ref::<tcb_t>(region_base + TCB_OFFSET);
            tcb.init();
            tcb.tcbTimeSlice = CONFIG_TIME_SLICE;
            tcb.domain = get_current_domain();
            unsafe {
                tcbDebugAppend(tcb as *mut tcb_t);
            }
            return cap_t::new_thread_cap(tcb.get_ptr());
        }

        ObjectType::EndpointObject => cap_t::new_endpoint_cap(0, 1, 1, 1, 1, region_base),

        ObjectType::NotificationObject => cap_t::new_notification_cap(0, 1, 1, region_base),

        ObjectType::CapTableObject => cap_t::new_cnode_cap(user_size, 0, 0, region_base),

        ObjectType::UnytpedObject => cap_t::new_untyped_cap(0, device_mem, user_size, region_base),

        ObjectType::PageTableObject => cap_t::new_page_table_cap(asidInvalid, region_base, 0, 0),

        ObjectType::NormalPageObject | ObjectType::GigaPageObject | ObjectType::MegaPageObject => {
            cap_t::new_frame_cap(
                asidInvalid,
                region_base,
                obj_type.get_frame_type(),
                VMReadWrite,
                device_mem as usize,
                0,
            )
        }
    }
}

pub fn reset_untyped_cap(srcSlot: &mut cte_t) -> exception_t {
    let prev_cap = &mut (*srcSlot).cap;
    let block_size = prev_cap.get_untyped_block_size();
    let region_base = prev_cap.get_untyped_ptr();
    let chunk = CONFIG_RESET_CHUNK_BITS;
    let offset = FREE_INDEX_TO_OFFSET(prev_cap.get_untyped_free_index());
    let device_mem = prev_cap.get_frame_is_device();
    if offset == 0 {
        return exception_t::EXCEPTION_NONE;
    }

    if device_mem != 0 && block_size < chunk {
        if device_mem != 0 {
            clear_memory(region_base as *mut u8, block_size);
        }
        prev_cap.set_untyped_free_index(0);
    } else {
        let mut offset: isize = ROUND_DOWN!(offset - 1, chunk) as isize;
        while offset != -(BIT!(chunk) as isize) {
            clear_memory(
                GET_OFFSET_FREE_PTR(region_base, offset as usize) as *mut u8,
                chunk,
            );
            offset -= BIT!(chunk) as isize;
        }
        prev_cap.set_untyped_free_index(OFFSET_TO_FREE_IDNEX(offset as usize));
    }
    exception_t::EXCEPTION_NONE
}

pub fn invoke_untyped_retype(
    src_slot: &mut cte_t,
    reset: bool,
    retype_base: pptr_t,
    new_type: ObjectType,
    user_size: usize,
    dest_cnode: &mut cte_t,
    dest_offset: usize,
    dest_length: usize,
    device_mem: usize,
) -> exception_t {
    let region_base = src_slot.cap.get_untyped_ptr();
    if reset {
        let status = reset_untyped_cap(src_slot);
        if status != exception_t::EXCEPTION_NONE {
            return status;
        }
    }

    let total_object_size = dest_length << new_type.get_object_size(user_size);
    let free_ref = retype_base + total_object_size;
    src_slot
        .cap
        .set_untyped_free_index(GET_FREE_INDEX(region_base, free_ref));
    create_new_objects(
        new_type,
        src_slot,
        dest_cnode,
        dest_offset,
        dest_length,
        retype_base,
        user_size,
        device_mem,
    );
    exception_t::EXCEPTION_NONE
}
