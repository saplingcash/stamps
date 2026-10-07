//! NU7 on mainnet.
//!
//! Zcash sets mainnet's NU7 activation height on 2026-10-20, after every librustzcash release our signers
//! can use. So the height is PINNED here, once, and every signer and reader of ours builds its consensus
//! parameters through [`Pinned`]: on mainnet, `BranchId::for_height` answers NU7 from the pin and nothing
//! else. Testnet's height (4,465,026, live since 2026-10-04) comes from librustzcash.
//!
//! Until the pin is set every mainnet height is NU6.3. A node that already reports NU7 then fails every
//! build loudly, in the branch compare each builder does against the node's branch, instead of signing
//! under a guessed branch.

/// Mainnet's NU7 activation height. Empty until Zcash sets it (2026-10-20); then the number, nothing else.
pub const NU7_MAINNET_ACTIVATION: Option<u32> = None;

/// NU7's consensus branch id (ZIP 259).
pub const NU7_BRANCH_ID: u32 = 0x7719_0AD9;

/// NU6.3's consensus branch id (Ironwood), the branch mainnet runs before NU7.
pub const NU6_3_BRANCH_ID: u32 = 0x37A5_165B;

#[cfg(feature = "proof")]
pub use params::{check, mainnet, testnet, Pinned};

#[cfg(feature = "proof")]
mod params {
    use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters, TestNetwork};

    /// Consensus parameters with mainnet's NU7 height taken from [`super::NU7_MAINNET_ACTIVATION`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Pinned<P>(pub P);

    impl<P: Parameters> Parameters for Pinned<P> {
        fn network_type(&self) -> NetworkType {
            self.0.network_type()
        }

        fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
            match (nu, self.0.network_type()) {
                (NetworkUpgrade::Nu7, NetworkType::Main) => super::NU7_MAINNET_ACTIVATION.map(BlockHeight::from_u32),
                _ => self.0.activation_height(nu),
            }
        }
    }

    /// Mainnet, with the pinned NU7 height.
    pub fn mainnet() -> Pinned<MainNetwork> {
        Pinned(MainNetwork)
    }

    /// Testnet (NU7 at 4,465,026, from librustzcash).
    pub fn testnet() -> Pinned<TestNetwork> {
        Pinned(TestNetwork)
    }

    /// The startup check every binary runs: the pin and librustzcash must not disagree. When a librustzcash
    /// release carries a mainnet height of its own, it has to equal the pin; a different number is a
    /// configuration error, and the process stops before it signs anything.
    pub fn check() -> Result<(), String> {
        if let (Some(lib), Some(pin)) = (MainNetwork.activation_height(NetworkUpgrade::Nu7), super::NU7_MAINNET_ACTIVATION) {
            if u32::from(lib) != pin {
                return Err(format!("librustzcash activates NU7 on mainnet at {lib} but the pin says {pin} (stamper-core src/nu7.rs)"));
            }
        }
        if u32::from(BranchId::Nu7) != super::NU7_BRANCH_ID {
            return Err("librustzcash's NU7 branch id is not ZIP 259's".into());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn mainnet_follows_the_pin() {
            let m = mainnet();
            let h = BlockHeight::from_u32(3_428_143); // NU6.3's own activation
            assert_eq!(BranchId::for_height(&m, h), BranchId::Nu6_3);
            match super::super::NU7_MAINNET_ACTIVATION {
                None => {
                    assert_eq!(m.activation_height(NetworkUpgrade::Nu7), None);
                    assert_eq!(BranchId::for_height(&m, BlockHeight::from_u32(u32::MAX - 1)), BranchId::Nu6_3);
                }
                Some(p) => {
                    assert_eq!(m.activation_height(NetworkUpgrade::Nu7), Some(BlockHeight::from_u32(p)));
                    assert_eq!(BranchId::for_height(&m, BlockHeight::from_u32(p - 1)), BranchId::Nu6_3);
                    assert_eq!(BranchId::for_height(&m, BlockHeight::from_u32(p)), BranchId::Nu7);
                }
            }
            // everything before NU7 is librustzcash's, untouched
            for nu in [NetworkUpgrade::Sapling, NetworkUpgrade::Nu5, NetworkUpgrade::Nu6, NetworkUpgrade::Nu6_3] {
                assert_eq!(m.activation_height(nu), MainNetwork.activation_height(nu));
            }
        }

        #[test]
        fn testnet_is_librustzcash_s() {
            let t = testnet();
            assert_eq!(t.activation_height(NetworkUpgrade::Nu7), Some(BlockHeight::from_u32(4_465_026)));
            assert_eq!(BranchId::for_height(&t, BlockHeight::from_u32(4_465_025)), BranchId::Nu6_3);
            assert_eq!(BranchId::for_height(&t, BlockHeight::from_u32(4_465_026)), BranchId::Nu7);
        }

        #[test]
        fn the_branch_ids_are_zip_259_s() {
            assert_eq!(u32::from(BranchId::Nu7), super::super::NU7_BRANCH_ID);
            assert_eq!(u32::from(BranchId::Nu6_3), super::super::NU6_3_BRANCH_ID);
            assert_eq!(check(), Ok(()));
        }
    }
}
