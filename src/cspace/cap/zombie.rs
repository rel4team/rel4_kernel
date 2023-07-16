use super::{cap_t, CapTag};


impl cap_t {

    #[inline]
    pub fn new_zombie_cap(capZombieID: usize, capZombieType: usize) -> Self {
        let mut cap = cap_t::default();
        /* fail if user has passed bits that we will override */
        assert!(
            (capZombieType & !0x7fusize)
                == (if true && (capZombieType & (1usize << 38)) != 0 {
                    0x0
                } else {
                    0
                })
        );

        cap.words[0] = 0
            | (CapTag::CapZombieCap as usize & 0x1fusize) << 59
            | (capZombieType & 0x7fusize) << 0;
        cap.words[1] = 0 | capZombieID << 0;
        cap
    }

    #[inline]
    pub fn get_zombie_id(&self) -> usize {
        (self.words[1] & 0xffffffffffffffffusize) >> 0
    }

    #[inline]
    pub fn set_zombie_id(&mut self, v64: usize) {
        assert!(
            (((!0xffffffffffffffffusize >> 0) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
    
        self.words[1] &= !0xffffffffffffffffusize;
        self.words[1] |= (v64 << 0) & 0xffffffffffffffffusize;
    }

    #[inline]
    pub fn get_zombie_type(&self) -> usize {
        (self.words[0] & 0x7fusize) >> 0
    }
}

#[inline]
pub fn cap_zombie_cap_new(capZombieID: usize, capZombieType: usize) -> cap_t {
    cap_t::new_zombie_cap(capZombieID, capZombieType)
}

#[inline]
pub fn cap_zombie_cap_get_capZombieID(cap: &cap_t) -> usize {
    cap.get_zombie_id()
}

#[inline]
pub fn cap_zombie_cap_set_capZombieID(cap: &mut cap_t, v64: usize) {
    cap.set_zombie_id(v64)
}

#[inline]
pub fn cap_zombie_cap_get_capZombieType(cap: &cap_t) -> usize {
    cap.get_zombie_type()
}