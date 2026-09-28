use std::sync::Mutex;

use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::{CrtGlweAutomorphismWorkspace, DcrtGadgetDomain, DcrtGlweTraceWorkspace};

/// Reusable workspace for serial DCRT coefficient expansion.
pub type DcrtGlweExpandCoeffWorkspace<T> = DcrtGlweTraceWorkspace<T>;

/// Preallocated, thread-safe workspace pool for parallel coefficient expansion.
///
/// Workspaces are returned to the pool after each worker finishes. Parallel
/// expansion performs no pool allocation. All workspaces are constructed from
/// one domain. Callers must use a domain with the same gadget layout and RNS
/// big-integer limb width when running expansion; acquiring a workspace does
/// not rebind or validate it.
pub struct DcrtGlweExpandCoeffSyncPool<T: FheUint> {
    workspaces: Mutex<Vec<DcrtGlweExpandCoeffWorkspace<T>>>,
}

impl<T: FheUint> DcrtGlweExpandCoeffSyncPool<T> {
    /// Creates a pool sized for the current Rayon thread count.
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
            .map(|_| DcrtGlweExpandCoeffWorkspace::from_parameters(parameters))
            .collect();
        Self {
            workspaces: Mutex::new(workspaces),
        }
    }

    fn acquire(&self) -> DcrtGlweExpandCoeffWorkspace<T> {
        self.workspaces
            .lock()
            .unwrap()
            .pop()
            .expect("DCRT expansion workspace pool capacity is smaller than its parallel demand")
    }

    fn release(&self, workspace: DcrtGlweExpandCoeffWorkspace<T>) {
        self.workspaces.lock().unwrap().push(workspace);
    }

    pub(super) fn acquire_guard(&self) -> DcrtPoolGuard<'_, T> {
        DcrtPoolGuard {
            workspace: Some(self.acquire()),
            pool: self,
        }
    }
}

pub(super) struct DcrtPoolGuard<'a, T: FheUint> {
    workspace: Option<DcrtGlweExpandCoeffWorkspace<T>>,
    pool: &'a DcrtGlweExpandCoeffSyncPool<T>,
}

impl<T: FheUint> DcrtPoolGuard<'_, T> {
    pub(super) fn as_mut(
        &mut self,
    ) -> (
        &mut primus_lattice::glwe::DcrtGlwe<Vec<T>>,
        &mut CrtGlweAutomorphismWorkspace<T>,
    ) {
        self.workspace.as_mut().unwrap().as_mut()
    }
}

impl<T: FheUint> Drop for DcrtPoolGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(workspace) = self.workspace.take() {
            self.pool.release(workspace);
        }
    }
}
