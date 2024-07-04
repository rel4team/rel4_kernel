use super::consts::*;
use super::{Gic_Cpu_Iface_Map, Gic_Dist_Map};
use aarch64_cpu::registers::Readable;
use tock_registers::interfaces::Writeable;

static GIC_DIST: Gic_Dist_Map = Gic_Dist_Map::new(GIC_V2_DISTRIBUTOR_PPTR as *mut u8);
static GIC_CPUIFACE: Gic_Cpu_Iface_Map = Gic_Cpu_Iface_Map::new(GIC_V2_CONTROLLER_PPTR as *mut u8);
// This is for aarch64 only
pub fn cpu_iface_init() {
    GIC_DIST.regs().enable_clr[0].set(IRQ_SET_ALL);
    GIC_DIST.regs().pending_clr[0].set(IRQ_SET_ALL);
    GIC_DIST.regs().security[0].set(0);
    GIC_DIST.regs().priority[0].set(0x0);

    let mut i = 0;
    while i < 16 {
        GIC_DIST.regs().sgi_pending_clr[i >> 2].set(IRQ_SET_ALL);
        i += 4;
    }

    GIC_CPUIFACE.regs().icontrol.set(0);
    GIC_CPUIFACE.regs().pri_msk_c.set(0);
    GIC_CPUIFACE.regs().pb_c.set(0);
    let mut i = GIC_CPUIFACE.regs().int_ack.get();
    while (i & IRQ_MASK) != IRQ_NONE {
        GIC_CPUIFACE.regs().eoi.set(0);
        i = GIC_CPUIFACE.regs().int_ack.get();
    }
    GIC_CPUIFACE.regs().icontrol.set(1);
}

pub fn cpu_initLocalIRQController() {
    cpu_iface_init();
}
