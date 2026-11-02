//! Deterministic pseudo-random numbers (research R2): SplitMix64, seeded per iteration so every
//! iteration is reproducible on its own. Not cryptographic, and it does not need to be.

const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

/// FNV-1a, 64 bit: hashes a target name into the per-iteration seed.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

/// SplitMix64 generator.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// `SplitMix64(seed ^ fnv1a64(target) ^ iter * golden)`: pure in its arguments.
    pub fn for_iteration(seed: u64, target: &str, iter: u64) -> Self {
        Self::new(seed ^ fnv1a64(target.as_bytes()) ^ iter.wrapping_mul(GOLDEN))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(GOLDEN);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (0 when `n` is 0). Modulo bias is irrelevant here.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }

    /// An index in `0..n` (0 when `n` is 0).
    pub fn index(&mut self, n: usize) -> usize {
        self.below(n as u64) as usize
    }

    /// A value in `lo..=hi`.
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.index(hi.saturating_sub(lo) + 1)
    }

    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    pub fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.index(items.len())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_matches_the_reference_vectors_for_seed_zero() {
        let mut rng = Rng::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn splitmix64_matches_the_reference_vectors_for_a_fixed_seed() {
        let mut rng = Rng::new(1_234_567);
        assert_eq!(rng.next_u64(), 6_457_827_717_110_365_317);
        assert_eq!(rng.next_u64(), 3_203_168_211_198_807_973);
        assert_eq!(rng.next_u64(), 9_817_491_932_198_370_423);
    }

    #[test]
    fn fnv1a64_matches_the_published_vectors() {
        assert_eq!(fnv1a64(b""), 0xCBF2_9CE4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xAF63_DC4C_8601_EC8C);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_F739_67E8);
    }

    #[test]
    fn the_default_seed_is_the_documented_constant() {
        assert_eq!(crate::DEFAULT_SEED, 0x5057_5359_4E43_0008);
    }

    #[test]
    fn an_iteration_stream_is_pure_and_independent_of_earlier_iterations() {
        let first: Vec<u64> = {
            let mut rng = Rng::for_iteration(7, "frame", 42);
            (0..4).map(|_| rng.next_u64()).collect()
        };
        // Consume other iterations first: iteration 42 must not change.
        for iter in 0..42 {
            let mut other = Rng::for_iteration(7, "frame", iter);
            other.next_u64();
        }
        let again: Vec<u64> = {
            let mut rng = Rng::for_iteration(7, "frame", 42);
            (0..4).map(|_| rng.next_u64()).collect()
        };
        assert_eq!(first, again);
    }

    #[test]
    fn different_targets_or_iterations_give_different_streams() {
        let a = Rng::for_iteration(7, "frame", 1).next_u64();
        let b = Rng::for_iteration(7, "hello", 1).next_u64();
        let c = Rng::for_iteration(7, "frame", 2).next_u64();
        let d = Rng::for_iteration(8, "frame", 1).next_u64();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn below_stays_in_range_and_handles_one() {
        let mut rng = Rng::new(3);
        for _ in 0..1000 {
            assert!(rng.below(7) < 7);
            assert_eq!(rng.below(1), 0);
        }
        assert_eq!(rng.below(0), 0);
    }
}
