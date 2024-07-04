use sel4_common::plus_define_bitfield;

// 两个机器字组成，维护一个双向链表，其中还有revocable和firstbadged两个标志位字段。
//
// revocable：可以在不通知对象持有者的情况下被删除或撤销。
//
// firstbadged：表示此能力是否是具有相同对象和相同类型的一组能力中的第一个被赋予badge的能力。

plus_define_bitfield! {
    mdb_node_t, 2, 0, 0, 0 => {
        new, 0 => {
            mdbNext, get_next, set_next, 1, 2, 37, 2, true,
            mdbRevocable, get_revocable, set_revocable, 1, 1, 1, 0, false,
            mdbFirstBadged, get_first_badged, set_first_badged, 1, 0, 0, 0, false,
            mdbPrev, get_prev, set_prev, 0, 0, 64, 0, false
        }
    }
}
