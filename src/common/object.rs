use super::sel4_config::*;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum ObjectType {
    UnytpedObject = 0,
    TCBObject,
    EndpointObject,
    NotificationObject,
    CapTableObject,
    #[cfg(feature = "ENABLE_ASYNC_SYSCALL")]
    ExecutorObject,
    GigaPageObject,
    NormalPageObject,
    MegaPageObject ,
    PageTableObject,
}

pub const seL4_ObjectTypeCount: usize = ObjectType::PageTableObject as usize + 1;


impl ObjectType {
    pub fn get_object_size(&self, user_object_size: usize) -> usize {
        #[cfg(feature = "ENABLE_ASYNC_SYSCALL")]
        if self.eq(&ObjectType::ExecutorObject) {
            return user_object_size
        }
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
            _ => {
                panic!("Invalid object: {:?}", self)
            }
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