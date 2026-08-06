use std::sync::Mutex;

use primus_integer::FheUint;
use primus_lattice::glwe::CrtGlwe;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::{CrtGlweAutoContext, CrtGlweTraceContext, DcrtGadgetDomain};

/// Reusable workspace for serial CRT coefficient expansion.
pub type CrtGlweExpandCoeffContext<T> = CrtGlweTraceContext<T>;

/// Preallocated, thread-safe workspace pool for parallel coefficient expansion.
///
/// Contexts are returned to the pool after each worker finishes. Parallel
/// expansion performs no pool allocation.
pub struct CrtGlweExpandCoeffSyncPool<T: FheUint> {
    contexts: Mutex<Vec<CrtGlweExpandCoeffContext<T>>>,
}

impl<T: FheUint> CrtGlweExpandCoeffSyncPool<T> {
    /// Creates a pool sized for the current Rayon thread count.
    pub fn new<M, Table>(domain: &DcrtGadgetDomain<'_, T, M, Table>) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        Self::with_capacity(rayon::current_num_threads(), domain)
    }

    /// Creates a pool containing exactly `capacity` preallocated contexts.
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
        let contexts = (0..capacity)
            .map(|_| CrtGlweExpandCoeffContext::from_parameters(parameters))
            .collect();
        Self {
            contexts: Mutex::new(contexts),
        }
    }

    fn acquire(&self) -> CrtGlweExpandCoeffContext<T> {
        self.contexts
            .lock()
            .unwrap()
            .pop()
            .expect("CRT expansion context pool capacity is smaller than its parallel demand")
    }

    fn release(&self, context: CrtGlweExpandCoeffContext<T>) {
        self.contexts.lock().unwrap().push(context);
    }

    pub(super) fn acquire_guard(&self) -> CrtPoolGuard<'_, T> {
        CrtPoolGuard {
            context: Some(self.acquire()),
            pool: self,
        }
    }
}

pub(super) struct CrtPoolGuard<'a, T: FheUint> {
    context: Option<CrtGlweExpandCoeffContext<T>>,
    pool: &'a CrtGlweExpandCoeffSyncPool<T>,
}

impl<T: FheUint> CrtPoolGuard<'_, T> {
    pub(super) fn as_mut(&mut self) -> (&mut CrtGlwe<Vec<T>>, &mut CrtGlweAutoContext<T>) {
        self.context.as_mut().unwrap().as_mut()
    }
}

impl<T: FheUint> Drop for CrtPoolGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(context) = self.context.take() {
            self.pool.release(context);
        }
    }
}
