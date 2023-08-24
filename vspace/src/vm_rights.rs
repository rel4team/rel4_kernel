use cspace::interface::seL4_CapRights_t;

pub const VMKernelOnly: usize = 1;
pub const VMReadOnly: usize = 2;
pub const VMReadWrite: usize = 3;


pub fn RISCVGetWriteFromVMRights(vm_rights: usize) -> bool {
    return vm_rights == VMReadWrite;
}

pub fn RISCVGetReadFromVMRights(vm_rights: usize) -> bool {
    return vm_rights != VMKernelOnly;
}

#[no_mangle]
pub fn maskVMRights(vmrights: usize, rights: seL4_CapRights_t) -> usize {
    if vmrights == VMReadOnly && rights.get_allow_read() != 0 {
        return VMReadOnly;
    }
    if vmrights == VMReadWrite && rights.get_allow_read() != 0 {
        if rights.get_allow_write() == 0 {
            return VMReadOnly;
        } else {
            return VMReadWrite;
        }
    }
    VMKernelOnly
}