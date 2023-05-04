use crate::{
    config::{seL4_CapRightsBits, seL4_MsgMaxLength},
    structures::{cap_transfer_t, seL4_CapRights_t, seL4_MessageInfo_t, vm_attributes_t, seL4_CNode_CapData_t},
    MASK,
};

#[inline]
#[no_mangle]
pub fn rightsFromWord(w: usize) -> seL4_CapRights_t {
    seL4_CapRights_t { word: w }
}

#[inline]
pub fn wordFromRights(rights: &seL4_CapRights_t) -> usize {
    rights.word & MASK!(seL4_CapRightsBits)
}

#[inline]
pub fn seL4_CapRights_get_capAllowGrantReply(rights: &seL4_CapRights_t) -> usize {
    let ret = (rights.word & 0x8usize) >> 3;
    ret
}

#[inline]
pub fn seL4_CapRights_get_capAllowGrant(rights: &seL4_CapRights_t) -> usize {
    let ret = (rights.word & 0x4usize) >> 2;
    ret
}

#[inline]
pub fn seL4_CapRights_get_capAllowRead(rights: &seL4_CapRights_t) -> usize {
    let ret = (rights.word & 0x2usize) >> 1;
    ret
}

#[inline]
pub fn seL4_CapRights_get_capAllowWrite(rights: &seL4_CapRights_t) -> usize {
    let ret = (rights.word & 0x1usize) >> 0;
    ret
}

#[inline]
pub fn vmRighsFromWord(w: usize) -> usize {
    w
}

#[inline]
pub fn wordFromVMRights(rights: usize) -> usize {
    rights
}

#[inline]
pub fn wordFromMEssageInfo(mi: seL4_MessageInfo_t) -> usize {
    mi.words[0]
}

#[inline]
pub fn seL4_MessageInfo_ptr_get_length(ptr: *const seL4_MessageInfo_t) -> usize {
    unsafe {
        let ret = (*ptr).words[0] & 0x7fusize;
        ret
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_set_length(ptr: *mut seL4_MessageInfo_t, v64: usize) {
    unsafe {
        (*ptr).words[0] &= !0x7fusize;
        (*ptr).words[0] |= v64 & 0x7f;
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_get_extraCaps(ptr: *const seL4_MessageInfo_t) -> usize {
    unsafe {
        let ret = ((*ptr).words[0] & 0x180usize) >> 7;
        ret
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_set_extraCaps(ptr: *mut seL4_MessageInfo_t, v64: usize) {
    unsafe {
        (*ptr).words[0] &= !0x180usize;
        (*ptr).words[0] |= (v64 << 7) & 0x180;
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_get_capsUnwrapped(ptr: *const seL4_MessageInfo_t) -> usize {
    unsafe {
        let ret = ((*ptr).words[0] & 0xe00usize) >> 9;
        ret
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_set_capsUnwrapped(ptr: *mut seL4_MessageInfo_t, v64: usize) {
    unsafe {
        (*ptr).words[0] &= !0xe00usize;
        (*ptr).words[0] |= (v64 << 9) & 0xe00;
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_get_label(ptr: *const seL4_MessageInfo_t) -> usize {
    unsafe {
        let ret = ((*ptr).words[0] & 0xfffffffffffff000usize) >> 12;
        ret
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_set_label(ptr: *mut seL4_MessageInfo_t, v64: usize) {
    unsafe {
        (*ptr).words[0] &= !0xfffffffffffff000usize;
        (*ptr).words[0] |= (v64 << 12) & 0xfffffffffffff000;
    }
}

#[inline]
pub fn seL4_MessageInfo_new(
    label: usize,
    capsUnwrapped: usize,
    extraCaps: usize,
    length: usize,
) -> seL4_MessageInfo_t {
    let seL4_MessageInfo = seL4_MessageInfo_t {
        words: [0
            | (label & 0xfffffffffffffusize) << 12
            | (capsUnwrapped & 0x7usize) << 9
            | (extraCaps & 0x3usize) << 7
            | (length & 0x7fusize) << 0],
    };

    seL4_MessageInfo
}

pub fn messageInfoFromWord_raw(w: usize) -> seL4_MessageInfo_t {
    let mi = seL4_MessageInfo_t { words: [w] };
    mi
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

pub fn messageInfoFromWord(w: usize) -> seL4_MessageInfo_t {
    let mi = seL4_MessageInfo_t { words: [w] };
    let len = seL4_MessageInfo_ptr_get_length((&mi) as *const seL4_MessageInfo_t);
    if len > seL4_MsgMaxLength {
        seL4_MessageInfo_ptr_set_length(
            (&mi) as *const seL4_MessageInfo_t as *mut seL4_MessageInfo_t,
            seL4_MsgMaxLength,
        );
    }
    mi
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