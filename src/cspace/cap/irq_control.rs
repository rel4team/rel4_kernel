use super::{Cap, CapTag};

#[derive(Clone, Copy, Debug)]
pub struct IRQControlCap {
    cap: Cap,
}

impl IRQControlCap {

    #[inline]
    pub fn new() -> Self {
        let mut cap = Cap::default();

        cap.words[0] = 0 | (CapTag::CapIrqControlCap as usize & 0x1fusize) << 59;
        cap.words[1] = 0;
        Self { cap }
    }
}