use common::{structures::exception_t, message_info::seL4_MessageInfo_t};
use ipc::cancel_ipc;
use task_manager::{tcb_t, badgeRegister, msgInfoRegister, get_currenct_thread, set_thread_state, ThreadState};

use crate::config::{n_frameRegisters, n_msgRegisters, msgRegister, frameRegisters, n_gpRegisters, gpRegisters};

#[no_mangle]
pub fn invokeTCB_ReadRegisters(src: &mut tcb_t, suspend_source: usize, n: usize, _arch: usize, call: bool) -> exception_t {
    let thread = get_currenct_thread();
    if suspend_source != 0 {
        cancel_ipc(src);
        src.suspend();
    }
    if call {
        let mut op_ipc_buffer = thread.lookup_mut_ipc_buffer(true);
        thread.set_register(badgeRegister, 0);
        let mut i: usize = 0;
        while i < n && i < n_frameRegisters && i < n_msgRegisters {
            // setRegister(thread, msgRegister[i], getRegister(src, frameRegisters[i]));
            thread.set_register(msgRegister[i], src.get_register(frameRegisters[i]));
            i += 1;
        }

        if let Some(ipc_buffer) = op_ipc_buffer.as_deref_mut() {
            while i < n && i < n_frameRegisters {
                ipc_buffer.msg[i] = src.get_register(frameRegisters[i]);
                i += 1;
            }
        }
        let j = i;
        i = 0;
        while i < n_gpRegisters && i + n_frameRegisters < n && i + n_frameRegisters < n_msgRegisters
        {
            thread.set_register(msgRegister[i + n_frameRegisters], src.get_register(gpRegisters[i]));
            i += 1;
        }

        if let Some(ipc_buffer) = op_ipc_buffer {
            while i < n_gpRegisters && i + n_frameRegisters < n {
                ipc_buffer.msg[i + n_frameRegisters] = src.get_register(gpRegisters[i]);
                i += 1;
            }
        }
        thread.set_register(msgInfoRegister, seL4_MessageInfo_t::new(0, 0, 0, i + j).to_word());
    }
    set_thread_state(thread, ThreadState::ThreadStateRunning);
    exception_t::EXCEPTION_NONE
}