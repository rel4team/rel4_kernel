use sel4_cspace::interface::seL4_CapRights_t;

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
pub fn maskVMRights(vm_rights: usize, rights: seL4_CapRights_t) -> usize {
    if vm_rights == VMReadOnly && rights.get_allow_read() != 0 {
        return VMReadOnly;
    }
    if vm_rights == VMReadWrite && rights.get_allow_read() != 0 {
        return if rights.get_allow_write() == 0 {
            VMReadOnly
        } else {
            VMReadWrite
        };
    }
    VMKernelOnly
}
