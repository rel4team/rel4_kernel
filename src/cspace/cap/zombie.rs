use super::{Cap, CapTag};

#[derive(Clone, Copy, Debug)]
pub struct ZombieCap {
    cap: Cap,
}

impl ZombieCap {

    #[inline]
    pub fn new(capZombieID: usize, capZombieType: usize) -> Self {
        let mut cap = Cap::default();
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
        Self { cap }
    }

    #[inline]
    pub fn get_id(&self) -> usize {
        (self.cap.words[1] & 0xffffffffffffffffusize) >> 0
    }

    #[inline]
    pub fn set_id(&mut self, v64: usize) {
        assert!(
            (((!0xffffffffffffffffusize >> 0) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
    
        self.cap.words[1] &= !0xffffffffffffffffusize;
        self.cap.words[1] |= (v64 << 0) & 0xffffffffffffffffusize;
    }

    #[inline]
    pub fn get_type(&self) -> usize {
        (self.cap.words[0] & 0x7fusize) >> 0
    }
}