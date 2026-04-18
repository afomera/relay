//! Per-engine DAL implementations. Public API lives on the crate root as
//! dispatcher fns that match on `Db` and forward to the right backend.

pub(crate) mod sqlite;
