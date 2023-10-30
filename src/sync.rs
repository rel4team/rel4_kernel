use crate::{common::sel4_config::CONFIG_MAX_NUM_NODES, vspace::pptr_t};

#[derive(Clone, Copy)]
pub enum clh_qnode_state_t {
    CLHState_Granted = 0,
    CLHState_Pending = 1,
}


#[derive(Clone, Copy)]
pub struct clh_qnode_t {
    pub value: clh_qnode_state_t,
    // TODO: Cache Line 对齐
}

impl Default for clh_qnode_t {
    fn default() -> Self {
        Self {
            value: clh_qnode_state_t::CLHState_Granted,
        }
    }
}


pub struct clh_qnode_p_t {
    pub node: pptr_t,
    pub next: pptr_t,
    pub ipi: usize,
    // TODO: Cache Line 对齐
}

pub struct clh_lock_t {
    pub nodes: [clh_qnode_t; CONFIG_MAX_NUM_NODES + 1],
    pub nodes_owner: [clh_qnode_p_t; CONFIG_MAX_NUM_NODES],
    pub head: pptr_t,
    // TODO: Cache Line 对齐
}

pub static mut big_kernel_lock: clh_lock_t = clh_lock_t {
    nodes: [clh_qnode_t {value: clh_qnode_state_t::CLHState_Granted }; CONFIG_MAX_NUM_NODES + 1],
    nodes_owner: [clh_qnode_p_t { node: 0, next: 0, ipi: 0 }; CONFIG_MAX_NUM_NODES],
    head: 0,
};

pub unsafe fn clh_lock_init() {
    for i in 0..CONFIG_MAX_NUM_NODES {
        big_kernel_lock.nodes_owner[i].node = &big_kernel_lock.nodes[i] as *const _ as usize;
        big_kernel_lock.nodes[CONFIG_MAX_NUM_NODES].value = clh_qnode_state_t::CLHState_Granted;
        big_kernel_lock.head = &big_kernel_lock.nodes[CONFIG_MAX_NUM_NODES] as *const _ as usize;
    }
}

pub unsafe fn clh_lock_acquire(cpu_idx: usize, irq_path: bool) {
    big_kernel_lock.nodes[cpu_idx].value = clh_qnode_state_t::CLHState_Pending;
    
}