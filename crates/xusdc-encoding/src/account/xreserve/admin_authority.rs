//! [`XReserveAdminAuthority`] — the account-wide authority configuration for the faucet's admin
//! surface, expressed as a per-procedure role assignment over the standard manager components.
//!
//! The faucet gives pausing to a dedicated pauser and the transfer blocklist to a dedicated
//! external administrator, and gives neither capability to the account that holds everything else.
//! The standard [`Authority`] component can express exactly that: under its RBAC mode each gated
//! procedure may carry its own required role, resolved at runtime from the calling procedure's
//! root, and a procedure with no assignment falls back to the built-in administrator role.
//!
//! This type owns that assignment. It is deliberately constructed without arguments: the four
//! procedure roots come from the standard manager components and the two role symbols are the
//! faucet's own constants, so there is no caller-supplied map that could gate a manager procedure
//! on the wrong role, or leave one ungated and silently fall through to the administrator. The
//! invariant holds because there is no way to express its violation.
//!
//! Two conversions make it usable: into the [`Authority`] configuration it describes, and into the
//! [`AccountComponent`] that carries it into an account.
//!
//! Installed by [`XReserveStablecoinBuilder::build_components`][crate::account::xreserve::XReserveStablecoinBuilder::build_components]
//! as the account's only authority component. One consequence is worth stating where a reader will
//! look for it: administrator membership is account-bound, and it is the account's ONLY authority
//! handle — the faucet installs no ownership component, so nothing else can move authority over the
//! unmapped setters. Rotating it is a grant to the incoming account then a revoke from the
//! outgoing one, both through the standard role-action note.

use std::collections::BTreeMap;

use miden_protocol::account::{AccountComponent, AccountProcedureRoot, RoleSymbol};
use miden_standards::account::access::{Authority, PausableManager};
use miden_standards::account::policies::BlocklistManager;

use super::{BLOCK_LISTER_ROLE, DOM_PAUSER_ROLE};

/// The number of manager procedures the faucet gates on a dedicated role: pause, unpause, block
/// and unblock. Every other authority-gated procedure on the account is left unassigned and so
/// resolves to the administrator role, which is where those capabilities sit today.
const ROLE_GATED_PROCEDURE_COUNT: usize = 4;

/// The faucet's account-wide authority: role-based, with a role assigned to each of the four
/// standard manager procedures the faucet exposes.
///
/// Pause and unpause are gated on the Circle Domain pauser role; block and unblock on the external
/// blocklist administrator role. Nothing else is assigned, so the remaining authority-gated
/// procedures — the attester setter, the supply cap and burn-floor setters, the policy setters and
/// the emergency switch — resolve to the built-in administrator role, keeping them with the
/// account that holds the administrator role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XReserveAdminAuthority {
    procedure_roles: BTreeMap<AccountProcedureRoot, RoleSymbol>,
}

impl XReserveAdminAuthority {
    /// Builds the faucet's authority configuration.
    ///
    /// Takes no arguments on purpose: the assignment is a property of the faucet's admin model, not
    /// a deployment parameter, so it cannot be misconfigured by a caller.
    pub fn new() -> Self {
        let pauser = RoleSymbol::new(DOM_PAUSER_ROLE)
            .expect("the Domain pauser role symbol is a fixed valid symbol");
        let block_lister = RoleSymbol::new(BLOCK_LISTER_ROLE)
            .expect("the blocklist administrator role symbol is a fixed valid symbol");

        let procedure_roles = BTreeMap::from([
            (PausableManager::pause_root(), pauser.clone()),
            (PausableManager::unpause_root(), pauser),
            (BlocklistManager::block_account_root(), block_lister.clone()),
            (BlocklistManager::unblock_account_root(), block_lister),
        ]);
        assert_eq!(
            procedure_roles.len(),
            ROLE_GATED_PROCEDURE_COUNT,
            "the four manager procedures must be four distinct roots",
        );

        Self { procedure_roles }
    }

    /// The role required to invoke each role-gated procedure, keyed by the procedure's root.
    pub fn procedure_roles(&self) -> &BTreeMap<AccountProcedureRoot, RoleSymbol> {
        &self.procedure_roles
    }
}

impl Default for XReserveAdminAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl From<XReserveAdminAuthority> for Authority {
    fn from(authority: XReserveAdminAuthority) -> Self {
        Authority::RbacControlled {
            procedure_roles: authority.procedure_roles,
        }
    }
}

impl From<XReserveAdminAuthority> for AccountComponent {
    fn from(authority: XReserveAdminAuthority) -> Self {
        Authority::from(authority).into()
    }
}
