use super::{cap::cap_t, mdb::mdb_node_t};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct cte_t {
    pub cap: cap_t,
    pub cteMDBNode: mdb_node_t,
}