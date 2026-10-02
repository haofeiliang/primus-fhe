//! CRT expansion layouts with shared pool ownership.

use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::workspace_pool::{WorkspaceGuard, WorkspacePool};
use crate::{CrtGlweTraceWorkspace, DcrtGadgetDomain};

/// Reusable workspace for serial CRT coefficient expansion.
pub type CrtGlweExpandCoeffWorkspace<T> = CrtGlweTraceWorkspace<T>;

/// Preallocated, thread-safe workspace pool for parallel coefficient expansion.
///
/// Workspaces are returned to the pool after each worker finishes. Parallel
/// expansion performs no pool allocation. All workspaces are constructed from
/// one domain. Callers must use a domain with the same gadget layout and RNS
/// big-integer limb width when running expansion; acquiring a workspace does
/// not rebind or validate it.
pub struct CrtGlweExpandCoeffSyncPool<T: FheUint> {
    workspaces: WorkspacePool<CrtGlweExpandCoeffWorkspace<T>>,
}

impl<T: FheUint> CrtGlweExpandCoeffSyncPool<T> {
    /// Creates a new [`CrtGlweExpandCoeffSyncPool`] sized for the current Rayon thread count.
    #[must_use]
    pub fn new<M, Table>(domain: &DcrtGadgetDomain<'_, T, M, Table>) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        Self::with_capacity(rayon::current_num_threads(), domain)
    }

    /// Creates a pool containing exactly `capacity` preallocated workspaces.
    ///
    /// `capacity` must cover the number of workers that can run concurrently.
    /// Prefer [`Self::new`] unless a custom Rayon pool has a known smaller size.
    #[must_use]
    pub fn with_capacity<M, Table>(
        capacity: usize,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let parameters = domain.parameters();
        let workspaces = (0..capacity)
            .map(|_| CrtGlweExpandCoeffWorkspace::from_parameters(parameters))
            .collect();
        Self {
            workspaces: WorkspacePool::new(workspaces),
        }
    }

    pub(super) fn acquire_guard(&self) -> WorkspaceGuard<'_, CrtGlweExpandCoeffWorkspace<T>> {
        self.workspaces.acquire()
    }
}
