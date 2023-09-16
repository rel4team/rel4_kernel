use common::{structures::exception_t, utils::convert_to_mut_type_ref, sel4_config::{seL4_PageTableBits, seL4_PageBits, asidInvalid}, message_info::seL4_MessageInfo_t};
use cspace::interface::{cap_t, cte_t, seL4_CapRights_t};
use task_manager::{get_currenct_thread, msgInfoRegister, set_thread_state, ThreadState};
use vspace::{pte_t, sfence, pptr_to_paddr, unmapPage, vm_attributes_t, maskVMRights};

use crate::{utils::clear_memory, config::badgeRegister, kernel::boot::current_lookup_fault};


pub fn invoke_page_table_unmap(cap: &mut cap_t) -> exception_t {
    if cap.get_pt_is_mapped() != 0 {
        let pt = convert_to_mut_type_ref::<pte_t>(cap.get_pt_base_ptr());
        pt.unmap_page_table(cap.get_pt_mapped_asid(), cap.get_pt_mapped_address());
        clear_memory(pt.get_ptr() as *mut u8, seL4_PageTableBits)
    }
    cap.set_pt_is_mapped(0);
    exception_t::EXCEPTION_NONE
}

pub fn invoke_page_table_map(pt_cap: &mut cap_t, pt_slot: &mut pte_t, asid: usize, vaddr: usize) -> exception_t {
    // let paddr = pptr_to_paddr(cap_page_table_cap_get_capPTBasePtr(cap));
    let paddr = pptr_to_paddr(pt_cap.get_pt_base_ptr());
    let pte = pte_t::new(
        paddr >> seL4_PageBits,
        0, /* sw */
        0, /* dirty (reserved non-leaf) */
        0, /* accessed (reserved non-leaf) */
        0, /* global */
        0, /* user (reserved non-leaf) */
        0, /* execute */
        0, /* write */
        0, /* read */
        1, /* valid */
    );
    pt_cap.set_pt_is_mapped(1);
    pt_cap.set_pt_mapped_asid(asid);
    pt_cap.set_pt_mapped_address(vaddr);
    *pt_slot = pte;
    sfence();
    exception_t::EXCEPTION_NONE
}


pub fn invoke_page_get_address(vbase_ptr: usize, call: bool) -> exception_t {
    let thread = get_currenct_thread();
    if call {
        thread.set_register(badgeRegister, 0);
        let length = thread.set_mr(0, vbase_ptr);
        thread.set_register(msgInfoRegister, seL4_MessageInfo_t::new(0, 0, 0, length).to_word());
    }
    set_thread_state(thread, ThreadState::ThreadStateRestart);
    exception_t::EXCEPTION_NONE
}

pub fn invoke_page_unmap(frame_cap: &mut cap_t, frame_slot: &mut cte_t) -> exception_t {
    if frame_cap.get_pt_mapped_asid() != asidInvalid {
        match unmapPage(frame_cap.get_frame_size(), frame_cap.get_frame_mapped_asid(),
        frame_cap.get_pt_mapped_address(), frame_cap.get_frame_base_ptr()) {
            Err(lookup_fault) => {
                unsafe { current_lookup_fault = lookup_fault; }
            }
            _ => {}
        }
    }
    frame_cap.set_frame_mapped_address(0);
    frame_cap.set_pt_mapped_asid(asidInvalid);
    frame_slot.cap = *frame_cap;
    exception_t::EXCEPTION_NONE
}


pub fn invoke_page_map(frame_cap: &mut cap_t, w_rights_mask: usize, vaddr: usize, asid: usize, attr: vm_attributes_t,
    pt_slot: &mut pte_t, frame_slot: &mut cte_t) -> exception_t {
    let frame_vm_rights = frame_cap.get_frame_vm_rights();
    let vm_rights = maskVMRights(frame_vm_rights, seL4_CapRights_t::from_word(w_rights_mask));
    let frame_addr = pptr_to_paddr(frame_cap.get_frame_base_ptr());
    frame_cap.set_frame_mapped_address(vaddr);
    frame_cap.set_frame_mapped_asid(asid);
    let executable = attr.get_execute_never() == 0;
    let pte = pte_t::make_user_pte(frame_addr, executable, vm_rights);
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    frame_slot.cap = *frame_cap;
    pt_slot.update(pte);
    exception_t::EXCEPTION_NONE
}