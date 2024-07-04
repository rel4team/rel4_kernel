//! This file contains the implementation of the `ObjectType` enum and its associated methods.
//! The `ObjectType` enum represents the different types of objects in the system.
//! It provides methods to retrieve the size of an object, the frame type of an object,
//! convert a usize value to an `ObjectType`, and check if an object type is architecture-specific.

use super::sel4_config::*;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
/// Represents the type of an object.
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

pub const seL4_ObjectTypeCount: usize = ObjectType::PageTableObject as usize + 1;

impl ObjectType {
    /// Returns the size of the object based on its type.
    ///
    /// # Arguments
    ///
    /// * `user_object_size` - The size of the user object.
    ///
    /// # Returns
    ///
    /// The size of the object.
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

    /// Returns the frame type of the object.
    ///
    /// # Returns
    ///
    /// The frame type of the object.
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

    /// Converts a usize value to an ObjectType.
    ///
    /// # Arguments
    ///
    /// * `value` - The usize value to convert.
    ///
    /// # Returns
    ///
    /// An Option containing the converted ObjectType, or None if the value is out of range.
    pub fn from_usize(value: usize) -> Option<Self> {
        if value >= seL4_ObjectTypeCount {
            return None;
        }
        unsafe { Some(core::mem::transmute::<u8, ObjectType>(value as u8)) }
    }

    /// Checks if the object type is an architecture-specific type.
    ///
    /// # Returns
    ///
    /// true if the object type is an architecture-specific type, false otherwise.
    pub fn is_arch_type(self) -> bool {
        match self {
            Self::GigaPageObject | Self::NormalPageObject | Self::MegaPageObject => true,
            _ => false,
        }
    }
}
