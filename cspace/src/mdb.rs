use core::intrinsics::unlikely;


/// 两个机器字组成，维护一个双向链表，其中还有revocable和firstbadged两个标志位字段。
/// 
/// revocable：可以在不通知对象持有者的情况下被删除或撤销。
/// 
/// firstbadged：表示此能力是否是具有相同对象和相同类型的一组能力中的第一个被赋予badge的能力。
#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, Default)]
pub struct mdb_node_t {
    pub words: [usize; 2],
}


impl mdb_node_t {
    
    #[inline]
    pub fn new(mdbNext: usize, mdbRevocable: usize, mdbFirstBadged: usize, mdbPrev: usize) -> Self {
        let mut mdb_node = mdb_node_t::default();

        mdb_node.words[0] = 0 | mdbPrev << 0;

        mdb_node.words[1] = 0
            | (mdbNext & 0x7ffffffffcusize) >> 0
            | (mdbRevocable & 0x1usize) << 1
            | (mdbFirstBadged & 0x1usize) << 0;
        mdb_node
    }

    #[inline]
    pub fn get_next(&self) -> usize {
        let mut ret: usize;
        ret = (self.words[1] & 0x7ffffffffcusize) << 0;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_next(&mut self, v64: usize) {
        assert!(
            (((!0x7ffffffffcusize << 0) | 0xffffff8000000000) & v64)
                == if true && (v64 & (1usize << (38))) != 0 {
                    0xffffff8000000000
                } else {
                    0
                }
        );
        self.words[1] = !0x7ffffffffcusize;
        self.words[1] |= (v64 >> 0) & 0x7ffffffffc;
    }

    #[inline]
    pub fn get_prev(&self) -> usize {
        let mut ret: usize;
        ret = (self.words[0] & 0xffffffffffffffffusize) >> 0;
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn set_prev(&mut self, v64: usize) {
        assert!(
            (((!0xffffffffffffffffusize >> 0) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
        self.words[0] &= !0xffffffffffffffffusize;
        self.words[0] |= (v64 << 0) & 0xffffffffffffffffusize;
    }

    #[inline]
    pub fn get_revocable(&self) -> usize {
        let mut ret: usize;
        ret = (self.words[1] & 0x2usize) >> 1;
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn get_first_badged(&self) -> usize {
        let mut ret: usize;
        ret = (self.words[1] & 0x1usize) >> 0;
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn set_revocable(&mut self, v64: usize) {
        assert!(
            (((!0x2usize >> 1) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
        self.words[1] &= !0x2usize;
        self.words[1] |= (v64 << 1) & 0x2;
    }

    #[inline]
    pub fn set_first_badged(&mut self, v64: usize) {
        assert!(
            (((!0x1usize >> 0) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
        self.words[1] &= !0x1usize;
        self.words[1] |= (v64 << 0) & 0x1usize;
    }
}