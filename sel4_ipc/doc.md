# endpoint
endpoint是一种基本的通信机制，用于线程（或进程）之间的同步和异步消息传递。endpoint允许线程以发送（Send）、接收（Recv）或回复（Reply）的形式进行通信。这些操作可以通过IPC（Inter-Process Communication）机制实现，允许线程之间安全地交换信息。
在rel4_kernel中，endpoint被表示为一个结构体（通过plus_define_bitfield!宏定义），其中包含了队列头部、队列尾部和状态等字段。这些字段用于管理通过endpoint发送和接收消息的tcb队列。EPState枚举定义了endpoint可能的状态，包括：
- Idle：表示endpoint当前没有进行任何消息传递操作。
- Send：表示有线程正在尝试通过endpoint发送消息。
- Recv：表示有线程正在尝试从endpoint接收消息。

## 方法解读
| 方法名              | 入参                                                                                                                                                                                 | 行为                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| cancel_ipc          | tcb                                                                                                                                                                                  | 取消该tcb在该endpoint上的ipc操作，如果该tcb是最后一个等待线程，取消后队列为空则将该endpoint的状态改为idle。最后把该线程的状态改为Inactive。                                                                                                                                                                                                                                                                                                                       |
| cancel_all_ipc      | 无                                                                                                                                                                                   | 把该endpoint上所有的等待线程放入调度队列中（取消ipc），并修改调度策略为ChooseNewThread                                                                                                                                                                                                                                                                                                                                                                            |
| cancel_badged_sends | badge                                                                                                                                                                                | 取消该endpoint上所有为badge标记的等待线程ipc，取消后队列为空则将该endpoint的状态改为idle。最后修改调度策略为ChooseNewThread                                                                                                                                                                                                                                                                                                                                       |
| send_ipc            | - src_thread: 发送IPC消息的线程</br>- blocking: 是否阻塞方式发送</br> - do_call: 是否是call方式 </br> - can_grant: 是否授权</br> - can_grant_reply: 是否授权回复 </br> - badge: 标记 | 如果当前endpoint是发送状态，则直接将调度策略修改为ChooseNewThread并将src_thread放入该endpoint的等待队列中。如果endpoint处于Recv状态，这意味着有另一个线程正在等待接收消息。函数首先从endpoint的队列中取出等待接收的线程，然后检查队列是否为空，如果为空，则将端点状态设置为Idle。接下来，执行IPC传输，将消息从源线程传输到目标线程。如果传输是一个调用（do_call为真），并且允许授予权限或回复授予权限，那么会设置caller cap；否则，将源线程的状态设置为Inactive。 |
| receive_ipc         | - thread: 需要接收ipc的线程</br> - is_blocking: 是否阻塞方式接收</br> - grant: 是否授权                                                                                              | 与send_ipc同理                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

# notification
notification是一种用于线程间通信（Inter-Process Communication, IPC）和同步的机制。notification对象可以被视为一种轻量级的信号量，它允许一个线程向一个或多个等待的线程发送信号，从而通知它们某个事件的发生或者某种条件已经满足。
具体来说，notification对象可以处于以下几种状态之一：
- Idle（空闲）：notification对象当前没有被任何线程等待或激活。
- Waiting（等待）：至少有一个线程正在等待notification对象的信号。
- Active（激活）：notification对象已经被激活，但尚未被任何等待线程接收。
notification对象通过signal操作被激活，当线程执行wait操作时，如果notification已经被激活，则线程会继续执行；如果notification未被激活，则线程会进入等待状态，直到notification被另一个线程激活。
## 字段解读
| 字段名         | 含义                               | 其他 |
| -------------- | ---------------------------------- | ---- |
| bound_tcb      | 用于表示与通知对象绑定的线程控制块 | -    |
| msg_identifier | 用于存储与通知相关的消息标识符     | -    |

## 方法解读
| 方法名 | 入参 | 行为 |
| ------ | ---- | ---- |
|active|badge|将当前对象的状态设置为激活，并将其消息标识符设置为传入的badge值|
|cancel_signal|tcb|从等待队列中移除该tcb，并更新相关状态，来取消对该tcb的信号。|
|cacncel_all_signal|-|类似上文中endpoint的cancel_all_ipc操作|
|send_signal|badge|在Idle状态下，函数尝试获取与通知对象绑定的TCB。如果成功获取到TCB，并且该TCB处于ThreadStateBlockedOnReceive状态（即，阻塞等待接收状态），则会取消TCB的当前进程间通信（IPC），将TCB的状态设置为Running（运行），更新TCB的寄存器以存储传入的信号值，最后尝试切换到该TCB。如果TCB不处于阻塞等待接收状态，或者没有绑定的TCB，函数则会调用active方法来激活通知对象并传递信号值。在Waiting状态下，如果队列不空，则取出队头作为接收线程，如果队列变空，则将通知对象的状态设置为Idle。接着，将TCB的状态设置为Running，更新TCB的寄存器以存储传入的信号值，最后尝试切换到该TCB。如果队列为空，则会触发panic。在Active状态下，这表示通知对象已经被激活，将其与传入的信号值进行按位或操作，相当于合并多个信号。|
|receive_signal|-|与send大致同理|
# transfer
transfer指的是在不同线程或进程之间传输信息、能力（capabilities）或者处理fault（faults）的过程。在给定的代码片段中，transfer是一个trait，定义了一系列与信息传输、能力传递、fault处理和信号完成相关的函数。这些函数允许线程（通过tcb_t结构体表示）之间进行通信和交互。
## 方法解读
| 方法名 | 入参 | 行为 |
| ------ | ---- | ---- |
|set_transfer_caps & set_transfer_caps_with_buf|-|用于设置在消息传递过程中要传输的额外能力（capabilities）。ipc_buffer参数允许传递一个缓冲区，以支持更复杂的传输需求。|
|do_fault_transfer|-|当线程遇到fault（如页面错误）时，使用此函数将fault信息传输给另一个线程（通常是错误处理线程）|
|do_normal_transfer|-|执行常规的信息传输，例如在线程间发送消息。它支持传递一个badge和一个授权标志（can_grant），以控制消息的权限。|
|do_fault_reply_transfer|-|在处理完fault后，使用此函数将回复传输给发生fault的线程。|
|complete_signal|-|完成信号处理的函数，用于事件或中断处理完成后的信号传递。|
|do_ipc_transfer|-|执行进程间通信（IPC）传输，类似于do_normal_transfer，但专门用于IPC场景。|
|do_reply|-|发送回复消息给另一个线程，通常在请求处理完成后使用。|
|cancel_ipc|-|取消当前线程的IPC操作。这通常发生在线程因为某些原因（如超时或任务取消）需要停止等待IPC完成时。|