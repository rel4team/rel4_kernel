
use crate::structures::cap_transfer_t;

#[inline]
pub fn vmRighsFromWord(w: usize) -> usize {
    w
}

#[inline]
pub fn wordFromVMRights(rights: usize) -> usize {
    rights
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
