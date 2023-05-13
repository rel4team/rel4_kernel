use super::{Cap, CapTag};

#[derive(Clone, Copy, Debug)]
pub struct IRQHandlerCap {
    cap: Cap,
}

impl IRQHandlerCap {

    #[inline]
    pub fn new(capIRQ: usize) -> Self {
        let mut cap = Cap::default();

        cap.words[0] = 0 | (CapTag::CapIrqHandlerCap as usize & 0x1fusize) << 59;
        cap.words[1] = 0 | (capIRQ & 0xfffusize) << 0;
        Self { cap }
    }

    #[inline]
    pub fn get_irq(&self) -> usize {
        (self.cap.words[1] & 0xfffusize) >> 0
    }
}