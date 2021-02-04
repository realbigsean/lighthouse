use crate::{MallocSizeOf, MallocSizeOfOps};
use core::num::NonZeroUsize;
use bls::{PublicKey, PublicKeyBytes, Signature, AggregateSignature};
use typenum::Unsigned;
use ssz_types::{FixedVector, VariableList, BitVector, BitList};
use bls::generics::GenericSignatureBytes;
use libp2p::{Multiaddr, PeerId};
use discv5::Enr;

malloc_size_of_is_0!(NonZeroUsize, PublicKey, PublicKeyBytes, Signature, AggregateSignature);
malloc_size_of_is_0!(any: GenericSignatureBytes<K1, K2>);
malloc_size_of_is_0!(Multiaddr, std::net::SocketAddr, Enr, PeerId, std::net::IpAddr);

impl<T,N> MallocSizeOf for FixedVector<T,N>
    where
        T: MallocSizeOf,
        N: Unsigned, {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.vec.size_of(ops)
    }
}

impl<T,N> MallocSizeOf for VariableList<T,N>
    where
        T: MallocSizeOf,
        N: Unsigned, {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.vec.size_of(ops)
    }
}

impl<N> MallocSizeOf for BitVector<N>
    where
        N: Unsigned, {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.bytes.size_of(ops)
    }
}

impl<N> MallocSizeOf for BitList<N>
    where
        N: Unsigned, {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.bytes.size_of(ops)
    }
}