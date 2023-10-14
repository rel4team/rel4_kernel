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