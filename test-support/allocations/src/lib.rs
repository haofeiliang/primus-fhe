//! Test/bench instrumentation. Counts successful allocations and
//! reallocations on the calling thread within `measure`. Byte counts are requested
//! sizes, excluding allocator overhead; they do not measure process memory.
//!
//! Each measuring test or benchmark binary must install [`CountingAllocator`]
//! with `#[global_allocator]`; merely importing this crate leaves its allocator unchanged.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

/// System allocator with opt-in, per-thread allocation measurement.
pub struct CountingAllocator;

#[derive(Clone, Copy, Debug, Default)]
pub struct Allocations {
    pub count: usize,
    pub allocated_bytes: usize,
    pub released_bytes: usize,
}

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<Allocations> = const { Cell::new(Allocations { count: 0, allocated_bytes: 0, released_bytes: 0 }) };
}

fn record(allocated: usize, released: usize, count: usize) {
    let _ = ACTIVE.try_with(|active| {
        if active.get() {
            COUNTS.with(|counts| {
                let previous = counts.get();
                counts.set(Allocations {
                    count: previous.count + count,
                    allocated_bytes: previous.allocated_bytes + allocated,
                    released_bytes: previous.released_bytes + released,
                });
            });
        }
    });
}

// SAFETY: every operation forwards the original pointer/layout to System. TLS
// accounting stores plain integers, never allocates or changes allocation contents.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record(layout.size(), 0, 1);
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record(layout.size(), 0, 1);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record(0, layout.size(), 0);
        unsafe {
            System.dealloc(pointer, layout);
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let output = unsafe { System.realloc(pointer, layout, size) };
        if !output.is_null() {
            record(size, layout.size(), 1);
        }
        output
    }
}

pub fn measure<R>(run: impl FnOnce() -> R) -> (R, Allocations) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(false));
        }
    }
    ACTIVE.with(|active| assert!(!active.get(), "nested allocation measurement"));
    COUNTS.with(|counts| counts.set(Allocations::default()));
    ACTIVE.with(|active| active.set(true));
    let reset = Reset;
    let result = run();
    drop(reset);
    (result, COUNTS.with(Cell::get))
}
