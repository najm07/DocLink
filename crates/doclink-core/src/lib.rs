//! doclink-core: shared protocol, identity, and discovery for DocLink.
//!
//! This crate is the language-neutral wire protocol made concrete —
//! everything here is defined by `docs/protocol.md` and is the
//! conformance target for any future client (C#, PrintLink interop).

pub mod cert;
pub mod discovery;
pub mod identity;
pub mod protocol;
