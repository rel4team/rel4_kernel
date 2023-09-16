use core::intrinsics::unlikely;

use crate::kernel::{
    boot::current_extra_caps,
    thread::getExtraCPtr,
};
use common::message_info::*;
use task_manager::*;

use common::{structures::{exception_t, seL4_IPCBuffer}, sel4_config::*};
use cspace::interface::*;

#[no_mangle]
pub fn lookupExtraCaps(
    thread: *mut tcb_t,
    bufferPtr: *mut usize,
    info: &seL4_MessageInfo_t,
) -> exception_t {
    unsafe {
        if bufferPtr as usize == 0 {
            current_extra_caps.excaprefs[0] = 0 as *mut cte_t;
            return exception_t::EXCEPTION_NONE;
        }
        let length = seL4_MessageInfo_ptr_get_extraCaps(info as *const seL4_MessageInfo_t);
        let mut i = 0;
        while i < length {
            let cptr = getExtraCPtr(bufferPtr, i);
            let lu_ret = lookupSlot(thread, cptr);
            if lu_ret.status != exception_t::EXCEPTION_NONE {
                panic!(" lookup slot error , found slot :{}", lu_ret.slot as usize);
            }
            current_extra_caps.excaprefs[i] = lu_ret.slot;
            i += 1;
        }
        if i < seL4_MsgMaxExtraCaps {
            current_extra_caps.excaprefs[i] = 0 as *mut cte_t;
        }
        return exception_t::EXCEPTION_NONE;
    }
}

pub fn lookup_extra_caps(thread: &tcb_t, op_buffer: Option<&seL4_IPCBuffer>, info: &seL4_MessageInfo_t) -> exception_t {
    match op_buffer {
        Some(buffer) => {
            let length = info.get_extra_caps();
            let mut i = 0;
            while i < length {
                let cptr = buffer.get_extra_cptr(i);
                let lu_ret = thread.lookup_slot(cptr);
                if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE)  {
                    panic!(" lookup slot error , found slot :{}", lu_ret.slot as usize);
                }
                unsafe {
                    current_extra_caps.excaprefs[i] = lu_ret.slot;
                }
                i += 1;
            }
            if i < seL4_MsgMaxExtraCaps {
                unsafe {
                    current_extra_caps.excaprefs[i] = 0 as *mut cte_t;
                }
            }
        }
        _ => {
            unsafe {
                current_extra_caps.excaprefs[0] = 0 as *mut cte_t;
            }
        }
    }
    return exception_t::EXCEPTION_NONE;
}

#[no_mangle]
pub fn copyMRs(
    sender: *mut tcb_t,
    sendBuf: *mut usize,
    receiver: *mut tcb_t,
    recvBuf: *mut usize,
    n: usize,
) -> usize {
    let mut i = 0;
    while i < n && i < n_msgRegisters {
        setRegister(
            receiver,
            msgRegister[i],
            getRegister(sender, msgRegister[i]),
        );
        i += 1;
    }

    if recvBuf as usize == 0 || sendBuf as usize == 0 {
        return i;
    }

    while i < n {
        unsafe {
            let recvPtr = recvBuf.add(i + 1);
            let sendPtr = sendBuf.add(i + 1);
            *recvPtr = *sendPtr;
            i += 1;
        }
    }
    i
}