# 切换时机
TCB切换时机：真正的线程调度组合为schedule()+restore_user_context()，其调用时机为系统调用handleSyscall、中断发生handleInterruptEntry、异常发生c_handle_exception。
# thread_state & structures

| 结构体/枚举名称                         | 含义                                                                                                                                                                                                                                                                                                                | 其他 |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- |
| ThreadState                             | 线程当前状态                                                                                                                                                                                                                                                                                                        |      |
| thread_state_t                          | - blocking_ipc_badge: ipc阻塞时的badge</br>- blocking_ipc_can_grant：ipc阻塞时是否可授权</br> - blocking_ipc_can_grant_relpy：ipc阻塞时是否可授权回复</br>- blocking_ipc_is_call：ipc阻塞时是否是调用</br>- tcb_queued：当前线程是否在队列中</br> - blocking_object：阻塞时阻塞队列的对象，endpoint或notification等 |      |
| ts_type                                 | 线程的state struct                                                                                                                                                                                                                                                                                                  |      |
| lookupSlot_raw_ret_t & lookupSlot_ret_t | 寻找Slot的结果                                                                                                                                                                                                                                                                                                      |      |

# tcb
| 方法名                     | 入参                                            | 行为                                                                                            |
| -------------------------- | ----------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| get_cspace                 | i                                               | 从当前tcb中获取第i个slot                                                                        |
| set_priority               | priority                                        | 将该线程从队列中弹出，修改其优先级，而后修改调度策略让其重新调度。                              |
| set_domain                 | dom                                             | 将该线程从队列中弹出，修改其domain值，而后修改调度策略让其重新调度。                            |
| sched_enqueue              | -                                               | 将当前线程放入调度队列，如果当前线程不在队列中，则使用domain和priority计算出所属队列。          |
| get_sched_queue            | index                                           | 获得index对应的就绪队列，只在入队出队时使用该方法用于获得线程所属队列。                         |
| sched_dequeue              | -                                               | 将当前线程弹出就绪队列，与sched_enqueue同理                                                     |
| sched_append               | -                                               | 将当前线程放入所属就绪队列的尾部                                                                |
| set_vm_root                | -                                               | 修改系统页表为当前线程页表，为后文切换线程打基础                                                |
| switch_to_this             | -                                               | 页表更新set_vm_root+修改当前线程ksCurThread，为后文的restore_user_context做准备                 |
| lookup_slot                | cap_ptr: 要寻找的cap                            | -                                                                                               |
| setup_reply_master         | -                                               | 创建一个reply cap，如果已经存在则不作操作                                                       |
| setup_caller_cap           | - sender：发送线程</br> - can_grant：是否可授权 | 它是用于在两个线程之间设置reply capability的。将sender的reply cap插入到接受者self中的caller cap |
| lookup_ipc_buffer          | is_receiver: 当前线程是否是接收者               | 计算出IPC缓冲区的实际内存地址                                                                   |
| lookup_extra_caps          | res：存放cap结果                                | 查找当前线程的ipc buffer中额外的cap                                                             |
| lookup_extra_caps_with_buf | - res：存放cap结果</br>- buf：已有的ipc buffer  | 查找ipc buffer中额外的cap                                                                       |
| set_mr                     | - offset：消息偏移</br>- reg：寄存器值          | 如果offset小于msg寄存器数量，则直接放入mr。否则需要放入ipc buffer中                             |
| set_lookup_fault_mrs       | 同上                                            | 同上                                                                                            |
| get_receive_slot           | -                                               | 从当前线程的ipc buffer中找到接收消息的slot                                                      |
| copy_mrs                   | - receiver：接收者线程</br>- length：消息长度   | 将当前线程的mr和ipc buffer（如果有），复制到receiver中                                          |
| copy_fault_mrs             | 同上                                            | 同上                                                                                            |
| copy_fault_mrs_for_reply   | 同上                                            | 同上                                                                                            |
| set_fault_mrs              | 同set_mr                                        | 同set_mr                                                                                        |
# scheduler
| 方法名                  | 入参 | 行为                                                                                                                                                                                                                                                                |
| ----------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| get_ks_scheduler_action | -    | 获得当前调度器行为：1. SchedulerAction_ResumeCurrentThread或SchedulerAction_ChooseNewThread，代表下一步调度行为。2. 否则则是线程指针                                                                                                                                |
| get_current_domain      | -    | 获得当前的调度domain                                                                                                                                                                                                                                                |
| getHighestPrio          | -    | 从位图中找到当前domain下的最高优先级                                                                                                                                                                                                                                |
| chooseThread            | -    | 从dom为0的域中选取优先级最高的线程，将其设置为当前线程等待上处理机。                                                                                                                                                                                                |
| rescheduleRequired      | -    | 修改下次的调度策略为重新选择新线程。                                                                                                                                                                                                                                |
| schedule                | -    | 这是整个调度的入口，使用之前设置的调度策略和优先级等指标进行调度，最终选择一个线程为current，等待后续上处理器；真正的线程调度组合为schedule()+restore_user_context()，其调用时机为系统调用handleSyscall、中断发生handleInterruptEntry、异常发生c_handle_exception。 |
| timerTick               | -    | 当前线程的时间片-1，如果已经没有了则发生调度。该函数只会在时钟中断发生时被调用。                                                                                                                                                                                    |
| activateThread          | -    | 确保当前线程是激活状态                                                                                                                                                                                                                                              |