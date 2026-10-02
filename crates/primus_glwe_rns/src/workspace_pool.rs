//! Shared ownership lifecycle for the CRT/DCRT expansion workspaces.

use std::sync::Mutex;

/// Preallocated scratch that each parallel expansion worker borrows exclusively.
/// Numerical layout and representation belong to the concrete workspace owner.
pub(crate) struct WorkspacePool<W> {
    workspaces: Mutex<Vec<W>>,
}

impl<W> WorkspacePool<W> {
    pub(crate) fn new(workspaces: Vec<W>) -> Self {
        Self {
            workspaces: Mutex::new(workspaces),
        }
    }

    /// Moves one prepared workspace into a guard without allocating; capacity
    /// must cover parallel demand. Drop returns it even if a worker unwinds.
    pub(crate) fn acquire(&self) -> WorkspaceGuard<'_, W> {
        let workspace = self.workspaces.lock().unwrap().pop().expect(
            "coefficient expansion workspace pool capacity is smaller than its parallel demand",
        );
        WorkspaceGuard {
            workspace: Some(workspace),
            pool: self,
        }
    }
}

/// Owns an exclusively borrowed workspace until the worker finishes.
pub(crate) struct WorkspaceGuard<'a, W> {
    workspace: Option<W>,
    pool: &'a WorkspacePool<W>,
}

impl<W> WorkspaceGuard<'_, W> {
    pub(crate) fn workspace_mut(&mut self) -> &mut W {
        self.workspace.as_mut().unwrap()
    }
}

impl<W> Drop for WorkspaceGuard<'_, W> {
    fn drop(&mut self) {
        if let Some(workspace) = self.workspace.take() {
            self.pool.workspaces.lock().unwrap().push(workspace);
        }
    }
}
