use std::sync::Mutex;

use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_reduce::FieldContext;

use crate::{CrtGlweAutoContext, DcrtGadgetDomain, DcrtGlweTraceContext};

pub type DcrtGlweExpandCoeffContext<T> = DcrtGlweTraceContext<T>;

/// Preallocated, thread-safe workspace pool for parallel coefficient expansion.
///
/// Contexts are returned to the pool after each worker finishes. Parallel
/// expansion performs no pool allocation.
pub struct DcrtGlweExpandCoeffSyncPool<T: FheUint> {
    contexts: Mutex<Vec<DcrtGlweExpandCoeffContext<T>>>,
}

impl<T: FheUint> DcrtGlweExpandCoeffSyncPool<T> {
    /// Creates a pool sized for the current Rayon thread count.
    pub fn new<M, Table>(domain: &DcrtGadgetDomain<'_, T, M, Table>) -> Self
    where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
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
        Table: DcrtTable<ValueT = T>,
    {
        let parameters = domain.parameters();
        let contexts = (0..capacity)
            .map(|_| DcrtGlweExpandCoeffContext::from_parameters(parameters))
            .collect();
        Self {
            contexts: Mutex::new(contexts),
        }
    }

    fn acquire(&self) -> DcrtGlweExpandCoeffContext<T> {
        self.contexts
            .lock()
            .unwrap()
            .pop()
            .expect("DCRT expansion context pool capacity is smaller than its parallel demand")
    }

    fn release(&self, context: DcrtGlweExpandCoeffContext<T>) {
        self.contexts.lock().unwrap().push(context);
    }

    pub(super) fn acquire_guard(&self) -> DcrtPoolGuard<'_, T> {
        DcrtPoolGuard {
            context: Some(self.acquire()),
            pool: self,
        }
    }
}

pub(super) struct DcrtPoolGuard<'a, T: FheUint> {
    context: Option<DcrtGlweExpandCoeffContext<T>>,
    pool: &'a DcrtGlweExpandCoeffSyncPool<T>,
}

impl<T: FheUint> DcrtPoolGuard<'_, T> {
    pub(super) fn as_mut(
        &mut self,
    ) -> (
        &mut primus_lattice::glwe::DcrtGlwe<Vec<T>>,
        &mut CrtGlweAutoContext<T>,
    ) {
        self.context.as_mut().unwrap().as_mut()
    }
}

impl<T: FheUint> Drop for DcrtPoolGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(context) = self.context.take() {
            self.pool.release(context);
        }
    }
}
