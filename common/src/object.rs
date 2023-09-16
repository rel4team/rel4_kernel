use crate::sel4_config::*;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum ObjectType {
    UnytpedObject = 0,
    TCBObject = 1,
    EndpointObject = 2,
    NotificationObject = 3,
    CapTableObject = 4,
    GigaPageObject = 5,
    NormalPageObject = 6,
    MegaPageObject = 7,
    PageTableObject = 8,
}

impl ObjectType {
    
}

pub const seL4_UntypedObject: usize = ObjectType::UnytpedObject as usize;
pub const seL4_TCBObject: usize = ObjectType::TCBObject as usize;
pub const seL4_EndpointObject: usize = ObjectType::EndpointObject as usize;
pub const seL4_NotificationObject: usize = ObjectType::NotificationObject as usize;
pub const seL4_CapTableObject: usize = ObjectType::CapTableObject as usize;
pub const seL4_NonArchObjectTypeCount: usize = ObjectType::CapTableObject as usize + 1;
pub const seL4_RISCV_Giga_Page: usize = ObjectType::GigaPageObject as usize;
pub const seL4_RISCV_4K_Page: usize = ObjectType::NormalPageObject as usize;
pub const seL4_RISCV_Mega_Page: usize = ObjectType::MegaPageObject as usize;
pub const seL4_RISCV_PageTableObject: usize = ObjectType::PageTableObject as usize;
pub const seL4_ObjectTypeCount: usize = ObjectType::PageTableObject as usize + 1;


impl ObjectType {
    pub fn get_object_size(&self, user_object_size: usize) -> usize {
        match self {
            ObjectType::UnytpedObject => user_object_size,
            ObjectType::TCBObject => seL4_TCBBits,
            ObjectType::EndpointObject => seL4_EndpointBits,
            ObjectType::NotificationObject => seL4_NotificationBits,
            ObjectType::CapTableObject => seL4_SlotBits + user_object_size,
            ObjectType::GigaPageObject => seL4_HugePageBits,
            ObjectType::NormalPageObject => seL4_PageBits,
            ObjectType::MegaPageObject => seL4_LargePageBits,
            ObjectType::PageTableObject => seL4_PageBits,
        }
    }

    pub fn get_frame_type(&self) -> usize {
        match self {
            ObjectType::NormalPageObject => RISCV_4K_Page,
            ObjectType::MegaPageObject => RISCV_Mega_Page,
            ObjectType::GigaPageObject => RISCV_Giga_Page,
            _ => {
                panic!("Invalid frame type: {:?}", self);
            }
        }
    }

    pub fn from_usize(value: usize) -> Option<Self> {
        if value >= seL4_ObjectTypeCount {
            return None;
        }
        unsafe {
           Some(core::mem::transmute::<u8, ObjectType>(value as u8))
        }
    }

    pub fn is_arch_type(self) -> bool {
        match self {
            Self::GigaPageObject | Self::NormalPageObject | Self::MegaPageObject => true,
            _ => false
        }
    }

}

pub fn getObjectSize(t: usize, userObjSize: usize) -> usize {
    unsafe {
        core::mem::transmute::<u8, ObjectType>(t as u8).get_object_size(userObjSize)
    }
}