
use crate::structures::{cap_transfer_t, vm_attributes_t, seL4_CNode_CapData_t};

#[inline]
pub fn vmRighsFromWord(w: usize) -> usize {
    w
}

#[inline]
pub fn wordFromVMRights(rights: usize) -> usize {
    rights
}

#[inline]
pub fn vm_attributes_new(value: usize) -> vm_attributes_t {
    vm_attributes_t {
        words: [value & 0x1usize],
    }
}

#[inline]
#[no_mangle]
pub fn vmAttributesFromWord(w: usize) -> vm_attributes_t {
    let attr = vm_attributes_t { words: [w] };
    attr
}

pub fn vm_attributes_get_riscvExecuteNever(vm_attributes: vm_attributes_t) -> usize {
    let ret = (vm_attributes.words[0] & 0x1usize) >> 0;
    ret
}

pub fn vm_attributes_set_riscvExecuteNever(
    mut vm_attributes: vm_attributes_t,
    v64: usize,
) -> vm_attributes_t {
    vm_attributes.words[0] &= !0x1usize;
    vm_attributes.words[0] |= (v64 << 0) & 0x1usize;
    return vm_attributes;
}

#[no_mangle]
pub fn capTransferFromWords(wptr: *mut usize) -> cap_transfer_t {
    unsafe {
        let ptr0 = wptr;
        let ptr1 = wptr.add(1);
        let ptr2 = wptr.add(2);
        let transfer = cap_transfer_t {
            ctReceiveRoot: *ptr0,
            ctReceiveIndex: *ptr1,
            ctReceiveDepth: *ptr2,
        };
        transfer
    }
}



#[inline]
pub fn seL4_CNode_capData_get_guard(seL4_CNode_CapData:&seL4_CNode_CapData_t)->usize{
    (seL4_CNode_CapData.words[0] & 0xffffffffffffffc0usize) >> 6
}

#[inline]
pub fn seL4_CNode_capData_get_guardSize(seL4_CNode_CapData:&seL4_CNode_CapData_t)->usize{
    (seL4_CNode_CapData.words[0] & 0x3fusize) >> 0
}