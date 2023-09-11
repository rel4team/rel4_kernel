#![feature(core_intrinsics)]
#![no_std]
#![feature(linkage)]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

//! CSpace模块为ReL4(seL4 的Rust重写) 提供了capability的抽象以及cspace的管理。
//!
//! # Examples
//!
//! ```
//! use cspace::{cte_t, cap_t, mdb_node_t};
//! use common::structures::exception_t;
//!
//! // 构建一个cnode cap和对应的slot
//! let cnode_cap = cap_t::new_cnode_cap(capCNodeRadix, capCNodeGuardSize, capCNodeGuard, capCNodePtr);
//! assert_eq!(cnode_cap.get_cap_type(), CapTag::CapCNodeCap);
//! let mut src_slot = cte_t { cap: cnode_cap, cteMDBNode: mdb_node_t::default() };
//!
//! // 构建一个空的dest，并将第一个slot的cap复制派生到dest中
//! let mut dest_slot = cte_t { cap: cap_t::new_null_cap(), cteMDBNode: mdb_node_t::default() };
//! let dc_ret = src_slot.derive_cap(cnode_cap);
//! cte_insert(&dc_ret.cap, src_slot, dest_slot);
//! assert!(src_slot.is_mdb_parent_of(dest_slot));
//!
//! // src slot通过revoke回收之前派生出去的cap
//! let _ = src_slot.revoke();
//! assert_eq!(src_slot.ensure_no_children(), exception_t::EXCEPTION_NONE);
//! ```


extern crate core;
mod cap;
mod utils;
mod mdb;
mod cte;
mod cap_rights;
mod structures;


/// 暴露给外部的接口
pub mod interface;
/// 需要外部实现的接口
pub mod deps;

/// 兼容c风格的接口，后续会删除
pub mod compatibility;