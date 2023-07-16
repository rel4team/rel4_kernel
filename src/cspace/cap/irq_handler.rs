use super::{cap_t, CapTag};


impl cap_t {

    #[inline]
    pub fn new_irq_handler_cap(capIRQ: usize) -> Self {
        let mut cap = cap_t::default();

        cap.words[0] = 0 | (CapTag::CapIrqHandlerCap as usize & 0x1fusize) << 59;
        cap.words[1] = 0 | (capIRQ & 0xfffusize) << 0;
        cap
    }

    #[inline]
    pub fn get_irq_handler(&self) -> usize {
        (self.words[1] & 0xfffusize) >> 0
    }
}