use crate::{MallocSizeOf, MallocSizeOfOps};
use core::num::NonZeroUsize;

impl MallocSizeOf for NonZeroUsize {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize {
        0
    }
    fn constant_size() -> Option<usize> {
        Some(0)
    }
}
