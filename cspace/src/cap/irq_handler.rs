use super::{cap_t, CapTag};

/// irq handler cap相关字段和方法
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

#[inline]
pub fn cap_irq_handler_cap_new(capIRQ: usize) -> cap_t {
    cap_t::new_irq_handler_cap(capIRQ)
}

#[inline]
pub fn cap_irq_handler_cap_get_capIRQ(cap: &cap_t) -> usize {
    cap.get_irq_handler()
}