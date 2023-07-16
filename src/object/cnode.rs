use crate::{config::tcbReply, kernel::thread::getCSpace, structures::tcb_t, cspace::interface::cap_reply_cap_new};


use crate::cspace::interface::*;

#[no_mangle]
pub fn setupReplyMaster(thread: *mut tcb_t) {
    let slot = getCSpace(thread as usize, tcbReply);
    unsafe {
        if cap_get_capType(&(*slot).cap) == cap_null_cap  {
            (*slot).cap = cap_reply_cap_new(1, 1, thread as usize);
            (*slot).cteMDBNode = mdb_node_new(0, 0, 0, 0);
            mdb_node_set_mdbRevocable(&mut (*slot).cteMDBNode, 1);
            mdb_node_set_mdbFirstBadged(&mut (*slot).cteMDBNode, 1);
        }
    }
}

