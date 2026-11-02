//! Seeds and mutators (FR-002, research R3). Seeds come from the project's own encoders at test
//! time; each input is a seed plus 1-4 mutations drawn from the iteration's [`Rng`].

use crate::rng::Rng;

/// Bytes that sit on common boundaries (sign bit, all ones, zero, one).
pub const BOUNDARY_BYTES: [u8; 5] = [0x00, 0x01, 0x7F, 0x80, 0xFF];

/// A 10-byte varint that decodes to 0 in a lenient decoder (non-minimal form).
pub const OVERLONG_VARINT: [u8; 10] = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00];

/// Longest prefix the deterministic truncation sweep visits per seed.
pub const SWEEP_MAX: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    U8,
    U16Be,
    U16Le,
    U32Be,
    U32Le,
    /// A postcard (LEB128) varint.
    Varint,
}

/// A length or count field an encoder wrote, with its documented bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    pub offset: usize,
    pub width: Width,
    pub bound: u64,
}

impl Field {
    pub fn new(offset: usize, width: Width, bound: u64) -> Self {
        Self {
            offset,
            width,
            bound,
        }
    }
}

/// One seed of a target's corpus.
#[derive(Clone, Debug)]
pub struct Seed {
    pub label: &'static str,
    pub bytes: Vec<u8>,
    pub fields: Vec<Field>,
    /// Stream targets only: where the bytes are split when delivered.
    pub chunks: Option<Vec<usize>>,
}

impl Seed {
    pub fn new(label: &'static str, bytes: Vec<u8>) -> Self {
        Self {
            label,
            bytes,
            fields: Vec::new(),
            chunks: None,
        }
    }

    pub fn field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    pub fn chunks(mut self, chunks: Vec<usize>) -> Self {
        self.chunks = Some(chunks);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    BitFlip,
    BoundaryByte,
    Insert,
    Delete,
    Truncate,
    Duplicate,
    Splice,
    LengthField,
    VarintBoundary,
    /// Stream targets only: new delivery split points.
    Rechunk,
}

const BYTE_MUTATIONS: [Mutation; 9] = [
    Mutation::BitFlip,
    Mutation::BoundaryByte,
    Mutation::Insert,
    Mutation::Delete,
    Mutation::Truncate,
    Mutation::Duplicate,
    Mutation::Splice,
    Mutation::LengthField,
    Mutation::VarintBoundary,
];

/// One generated input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    /// Index of the seed it was derived from.
    pub seed: usize,
    pub bytes: Vec<u8>,
    pub chunks: Option<Vec<usize>>,
    pub mutations: Vec<Mutation>,
    /// Whether the bytes or split points differ from the seed.
    pub mutated: bool,
}

impl Input {
    /// An input made of raw bytes (the optional cargo-fuzz entry).
    pub fn raw(seed: usize, bytes: &[u8]) -> Self {
        Self {
            seed,
            bytes: bytes.to_vec(),
            chunks: None,
            mutations: Vec::new(),
            mutated: true,
        }
    }

    /// The bytes split at the input's chunk points (one piece when it has none).
    pub fn pieces(&self) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut start = 0;
        for &point in self.chunks.iter().flatten() {
            if point > start && point < self.bytes.len() {
                out.push(&self.bytes[start..point]);
                start = point;
            }
        }
        out.push(&self.bytes[start..]);
        out
    }
}

/// Postcard (LEB128) encoding of `value`.
pub fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// Length of the varint starting at `offset` (bounded by 10 bytes and the input).
fn varint_len(bytes: &[u8], offset: usize) -> usize {
    let mut len = 0;
    while offset + len < bytes.len() && len < 10 {
        len += 1;
        if bytes[offset + len - 1] & 0x80 == 0 {
            break;
        }
    }
    len
}

/// `0, bound-1, bound, bound+1, max of the width` (saturating).
pub fn length_field_values(field: &Field) -> [u64; 5] {
    let max = match field.width {
        Width::U8 => 0xFF,
        Width::U16Be | Width::U16Le => 0xFFFF,
        Width::U32Be | Width::U32Le => 0xFFFF_FFFF,
        Width::Varint => u64::MAX,
    };
    [
        0,
        field.bound.saturating_sub(1),
        field.bound,
        field.bound.saturating_add(1),
        max,
    ]
}

/// Writes `value` into `field` (truncated to its width); a field past the end is ignored.
pub fn write_field(bytes: &mut Vec<u8>, field: &Field, value: u64) {
    let at = field.offset;
    let fits = |n: usize| at.checked_add(n).is_some_and(|end| end <= bytes.len());
    match field.width {
        Width::U8 if fits(1) => bytes[at] = value as u8,
        Width::U16Be if fits(2) => bytes[at..at + 2].copy_from_slice(&(value as u16).to_be_bytes()),
        Width::U16Le if fits(2) => bytes[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes()),
        Width::U32Be if fits(4) => bytes[at..at + 4].copy_from_slice(&(value as u32).to_be_bytes()),
        Width::U32Le if fits(4) => bytes[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes()),
        Width::Varint if fits(1) => {
            let old = varint_len(bytes, at);
            bytes.splice(at..at + old, varint(value));
        }
        _ => {}
    }
}

fn fill_byte(rng: &mut Rng) -> u8 {
    if rng.bool() {
        *rng.pick(&BOUNDARY_BYTES)
    } else {
        rng.byte()
    }
}

/// Applies one mutation in place. `seeds` is the corpus (for `Splice`).
pub fn apply(
    mutation: Mutation,
    bytes: &mut Vec<u8>,
    chunks: &mut Option<Vec<usize>>,
    seed: &Seed,
    seeds: &[Seed],
    rng: &mut Rng,
) {
    let len = bytes.len();
    match mutation {
        Mutation::BitFlip => {
            if len == 0 {
                bytes.push(rng.byte());
            } else {
                let at = rng.index(len);
                bytes[at] ^= 1 << rng.below(8);
            }
        }
        Mutation::BoundaryByte => {
            if len == 0 {
                bytes.push(*rng.pick(&BOUNDARY_BYTES));
            } else {
                let at = rng.index(len);
                bytes[at] = *rng.pick(&BOUNDARY_BYTES);
            }
        }
        Mutation::Insert => {
            let at = rng.index(len + 1);
            let n = rng.range(1, 16);
            let fill: Vec<u8> = (0..n).map(|_| fill_byte(rng)).collect();
            bytes.splice(at..at, fill);
        }
        Mutation::Delete => {
            if len > 0 {
                let at = rng.index(len);
                let n = rng.range(1, 16).min(len - at);
                bytes.drain(at..at + n);
            }
        }
        Mutation::Truncate => {
            if len > 0 {
                let to = rng.index(len);
                bytes.truncate(to);
            }
        }
        Mutation::Duplicate => {
            if len > 0 {
                let n = rng.range(1, len.min(64));
                let from = rng.index(len - n + 1);
                let to = rng.index(len + 1);
                let copy = bytes[from..from + n].to_vec();
                bytes.splice(to..to, copy);
            }
        }
        Mutation::Splice => {
            let other = if seeds.is_empty() {
                seed
            } else {
                rng.pick(seeds)
            };
            let cut = rng.index(len + 1);
            let from = rng.index(other.bytes.len() + 1);
            bytes.truncate(cut);
            bytes.extend_from_slice(&other.bytes[from..]);
        }
        Mutation::LengthField => {
            if seed.fields.is_empty() {
                apply(Mutation::BitFlip, bytes, chunks, seed, seeds, rng);
            } else {
                let field = *rng.pick(&seed.fields);
                let value = *rng.pick(&length_field_values(&field));
                write_field(bytes, &field, value);
            }
        }
        Mutation::VarintBoundary => {
            let values = [0, 127, 128, u64::from(u32::MAX), u64::MAX];
            let pick = rng.index(values.len() + 1);
            let encoded = if pick == values.len() {
                OVERLONG_VARINT.to_vec()
            } else {
                varint(values[pick])
            };
            let at = rng.index(len + 1);
            let replace = rng.bool() && at < len;
            let old = if replace { varint_len(bytes, at) } else { 0 };
            if replace && bytes[at..at + old] == encoded[..] {
                bytes.splice(at..at, encoded);
            } else {
                bytes.splice(at..at + old, encoded);
            }
        }
        Mutation::Rechunk => {
            let mut points = Vec::new();
            if len >= 2 {
                let n = rng.range(1, (len - 1).min(8));
                points = (0..n).map(|_| rng.range(1, len - 1)).collect();
                points.sort_unstable();
                points.dedup();
            }
            *chunks = Some(points);
        }
    }
}

/// Turns iteration numbers into inputs: first every seed unmutated, then a truncation sweep
/// over every prefix length up to [`SWEEP_MAX`], then random mutations.
pub struct Generator<'a> {
    seeds: &'a [Seed],
    cap: usize,
    /// Prefix sums of the per-seed sweep lengths.
    sweep_ends: Vec<u64>,
}

impl<'a> Generator<'a> {
    pub fn new(seeds: &'a [Seed], cap: usize) -> Self {
        Self::with_sweep(seeds, cap, true)
    }

    /// `sweep = false` skips the truncation sweep (targets whose prefixes are all expensive).
    pub fn with_sweep(seeds: &'a [Seed], cap: usize, sweep: bool) -> Self {
        let mut total = 0;
        let sweep_ends = seeds
            .iter()
            .map(|seed| {
                if sweep {
                    total += seed.bytes.len().min(SWEEP_MAX) as u64;
                }
                total
            })
            .collect();
        Self {
            seeds,
            cap,
            sweep_ends,
        }
    }

    pub fn sweep_len(&self) -> u64 {
        self.sweep_ends.last().copied().unwrap_or(0)
    }

    pub fn input(&self, iter: u64, rng: &mut Rng) -> Input {
        let n = self.seeds.len() as u64;
        if n == 0 {
            return Input::raw(0, &[]);
        }
        if iter < n {
            let seed = &self.seeds[iter as usize];
            return Input {
                seed: iter as usize,
                bytes: seed.bytes.clone(),
                chunks: seed.chunks.clone(),
                mutations: Vec::new(),
                mutated: false,
            };
        }
        let k = iter - n;
        if k < self.sweep_len() {
            let index = self.sweep_ends.partition_point(|end| *end <= k);
            let start = if index == 0 {
                0
            } else {
                self.sweep_ends[index - 1]
            };
            let seed = &self.seeds[index];
            let len = (k - start) as usize;
            let chunks = seed
                .chunks
                .as_ref()
                .map(|c| c.iter().copied().filter(|p| *p < len).collect());
            return self.finish(
                index,
                seed.bytes[..len].to_vec(),
                chunks,
                vec![Mutation::Truncate],
            );
        }
        let index = rng.index(self.seeds.len());
        let seed = &self.seeds[index];
        let mut bytes = seed.bytes.clone();
        let mut chunks = seed.chunks.clone();
        let count = rng.range(1, 4);
        let mut mutations = Vec::with_capacity(count);
        for _ in 0..count {
            let mutation = if seed.chunks.is_some() && rng.below(10) == 0 {
                Mutation::Rechunk
            } else {
                *rng.pick(&BYTE_MUTATIONS)
            };
            apply(mutation, &mut bytes, &mut chunks, seed, self.seeds, rng);
            mutations.push(mutation);
        }
        bytes.truncate(self.cap);
        self.finish(index, bytes, chunks, mutations)
    }

    fn finish(
        &self,
        index: usize,
        bytes: Vec<u8>,
        chunks: Option<Vec<usize>>,
        mutations: Vec<Mutation>,
    ) -> Input {
        let seed = &self.seeds[index];
        let mutated = bytes != seed.bytes || chunks != seed.chunks;
        Input {
            seed: index,
            bytes,
            chunks,
            mutations,
            mutated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    fn seed(bytes: &[u8]) -> Seed {
        Seed::new("t", bytes.to_vec())
    }

    fn rng(i: u64) -> Rng {
        Rng::for_iteration(1, "mutate-test", i)
    }

    #[test]
    fn bit_flip_changes_exactly_one_bit() {
        let s = seed(&[0u8; 32]);
        for i in 0..200 {
            let mut bytes = s.bytes.clone();
            apply(
                Mutation::BitFlip,
                &mut bytes,
                &mut None,
                &s,
                &[],
                &mut rng(i),
            );
            let ones: u32 = bytes.iter().map(|b| b.count_ones()).sum();
            assert_eq!(bytes.len(), 32);
            assert_eq!(ones, 1);
        }
    }

    #[test]
    fn boundary_byte_writes_only_boundary_values() {
        let s = seed(&[0x42u8; 16]);
        for i in 0..200 {
            let mut bytes = s.bytes.clone();
            apply(
                Mutation::BoundaryByte,
                &mut bytes,
                &mut None,
                &s,
                &[],
                &mut rng(i),
            );
            assert_eq!(bytes.len(), 16);
            let changed: Vec<u8> = bytes.iter().copied().filter(|b| *b != 0x42).collect();
            assert!(changed.len() <= 1);
            assert!(changed.iter().all(|b| BOUNDARY_BYTES.contains(b)));
        }
    }

    #[test]
    fn insert_adds_one_to_sixteen_bytes_and_delete_removes_one_to_sixteen() {
        let s = seed(&[7u8; 64]);
        for i in 0..200 {
            let mut bytes = s.bytes.clone();
            apply(
                Mutation::Insert,
                &mut bytes,
                &mut None,
                &s,
                &[],
                &mut rng(i),
            );
            assert!((65..=80).contains(&bytes.len()), "{}", bytes.len());
            let mut bytes = s.bytes.clone();
            apply(
                Mutation::Delete,
                &mut bytes,
                &mut None,
                &s,
                &[],
                &mut rng(i),
            );
            assert!((48..=63).contains(&bytes.len()), "{}", bytes.len());
        }
    }

    #[test]
    fn truncate_shortens_and_keeps_a_prefix() {
        let s = seed(&(0..100u8).collect::<Vec<_>>());
        for i in 0..200 {
            let mut bytes = s.bytes.clone();
            apply(
                Mutation::Truncate,
                &mut bytes,
                &mut None,
                &s,
                &[],
                &mut rng(i),
            );
            assert!(bytes.len() < 100);
            assert_eq!(&s.bytes[..bytes.len()], &bytes[..]);
        }
    }

    #[test]
    fn duplicate_copies_an_existing_range() {
        let s = seed(&(0..50u8).collect::<Vec<_>>());
        for i in 0..200 {
            let mut bytes = s.bytes.clone();
            apply(
                Mutation::Duplicate,
                &mut bytes,
                &mut None,
                &s,
                &[],
                &mut rng(i),
            );
            assert!(bytes.len() > 50 && bytes.len() <= 50 + 64);
            assert!(bytes.iter().all(|b| *b < 50));
        }
    }

    #[test]
    fn splice_joins_a_prefix_and_a_suffix_of_another_seed() {
        let a = seed(&[1u8; 40]);
        let b = seed(&[2u8; 40]);
        let all = [a, b];
        for i in 0..200 {
            let mut bytes = all[0].bytes.clone();
            apply(
                Mutation::Splice,
                &mut bytes,
                &mut None,
                &all[0],
                &all,
                &mut rng(i),
            );
            let ones = bytes.iter().take_while(|b| **b == 1).count();
            assert!(bytes[ones..].iter().all(|b| *b == 2 || *b == 1));
        }
    }

    #[test]
    fn length_field_values_are_the_five_documented_cases() {
        let f = Field::new(0, Width::U16Be, 1024);
        assert_eq!(length_field_values(&f), [0, 1023, 1024, 1025, 0xFFFF]);
        let f = Field::new(0, Width::U8, 0);
        assert_eq!(length_field_values(&f), [0, 0, 0, 1, 0xFF]);
        let f = Field::new(0, Width::U32Le, 79);
        assert_eq!(length_field_values(&f), [0, 78, 79, 80, 0xFFFF_FFFF]);
        let f = Field::new(0, Width::Varint, 512);
        assert_eq!(length_field_values(&f), [0, 511, 512, 513, u64::MAX]);
    }

    #[test]
    fn length_field_writes_at_the_offset_with_width_and_endianness() {
        let mut bytes = vec![0xAAu8; 8];
        write_field(&mut bytes, &Field::new(2, Width::U16Be, 0), 0x0102);
        assert_eq!(bytes, [0xAA, 0xAA, 0x01, 0x02, 0xAA, 0xAA, 0xAA, 0xAA]);
        let mut bytes = vec![0xAAu8; 8];
        write_field(&mut bytes, &Field::new(1, Width::U16Le, 0), 0x0102);
        assert_eq!(bytes, [0xAA, 0x02, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        let mut bytes = vec![0xAAu8; 8];
        write_field(&mut bytes, &Field::new(0, Width::U32Be, 0), 0x0102_0304);
        assert_eq!(&bytes[..4], &[1, 2, 3, 4]);
        let mut bytes = vec![0xAAu8; 8];
        write_field(&mut bytes, &Field::new(4, Width::U32Le, 0), 0x0102_0304);
        assert_eq!(&bytes[4..], &[4, 3, 2, 1]);
        let mut bytes = vec![0xAAu8; 3];
        write_field(&mut bytes, &Field::new(1, Width::U8, 0), 0x1FF);
        assert_eq!(bytes, [0xAA, 0xFF, 0xAA]);
        // A varint field is replaced by the new encoding (old one is 2 bytes here).
        let mut bytes = vec![0x01, 0x80, 0x01, 0x09];
        write_field(&mut bytes, &Field::new(1, Width::Varint, 0), 300);
        assert_eq!(bytes, [0x01, 0xAC, 0x02, 0x09]);
        // A field past the end is ignored.
        let mut bytes = vec![0u8; 2];
        write_field(&mut bytes, &Field::new(1, Width::U32Be, 0), 5);
        assert_eq!(bytes, [0, 0]);
    }

    #[test]
    fn length_field_mutation_uses_only_the_documented_values() {
        let s = Seed::new("f", vec![0u8; 4]).field(Field::new(0, Width::U16Be, 1024));
        let allowed = length_field_values(&s.fields[0]);
        for i in 0..100 {
            let mut bytes = s.bytes.clone();
            apply(
                Mutation::LengthField,
                &mut bytes,
                &mut None,
                &s,
                &[],
                &mut rng(i),
            );
            let value = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
            assert!(allowed.contains(&value), "{value}");
        }
    }

    #[test]
    fn varints_encode_like_postcard_and_overlong_has_ten_bytes() {
        assert_eq!(varint(0), [0]);
        assert_eq!(varint(127), [0x7F]);
        assert_eq!(varint(128), [0x80, 0x01]);
        assert_eq!(varint(u64::from(u32::MAX)), [0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        assert_eq!(varint(u64::MAX).len(), 10);
        assert_eq!(OVERLONG_VARINT.len(), 10);
        assert_eq!(OVERLONG_VARINT[9], 0);
    }

    #[test]
    fn varint_boundary_inserts_or_replaces_a_boundary_varint() {
        let s = seed(&[0x55u8; 20]);
        let mut grew = false;
        for i in 0..200 {
            let mut bytes = s.bytes.clone();
            apply(
                Mutation::VarintBoundary,
                &mut bytes,
                &mut None,
                &s,
                &[],
                &mut rng(i),
            );
            assert_ne!(bytes, s.bytes);
            grew |= bytes.len() > 20;
        }
        assert!(grew);
    }

    #[test]
    fn rechunk_sets_sorted_split_points_inside_the_input() {
        let s = Seed::new("stream", vec![9u8; 100]).chunks(vec![50]);
        for i in 0..100 {
            let mut bytes = s.bytes.clone();
            let mut chunks = s.chunks.clone();
            apply(
                Mutation::Rechunk,
                &mut bytes,
                &mut chunks,
                &s,
                &[],
                &mut rng(i),
            );
            let chunks = chunks.unwrap();
            assert!(chunks.windows(2).all(|w| w[0] < w[1]));
            assert!(chunks.iter().all(|c| *c > 0 && *c < 100));
        }
    }

    #[test]
    fn the_first_iterations_are_the_unmutated_seeds() {
        let seeds = vec![seed(&[1, 2, 3]), seed(&[4, 5])];
        let generator = Generator::new(&seeds, 64);
        for (i, s) in seeds.iter().enumerate() {
            let input = generator.input(i as u64, &mut rng(i as u64));
            assert_eq!(input.bytes, s.bytes);
            assert_eq!(input.seed, i);
            assert!(!input.mutated);
        }
    }

    #[test]
    fn the_truncation_sweep_visits_every_length_up_to_256() {
        let seeds = vec![seed(&[3u8; 300]), seed(&[4u8; 10])];
        let generator = Generator::new(&seeds, 1024);
        let mut lengths = [Vec::new(), Vec::new()];
        for iter in 2..(2 + generator.sweep_len()) {
            let input = generator.input(iter, &mut rng(iter));
            lengths[input.seed].push(input.bytes.len());
        }
        assert_eq!(lengths[0], (0..256).collect::<Vec<_>>());
        assert_eq!(lengths[1], (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn mutated_inputs_never_exceed_the_cap() {
        let seeds = vec![seed(&[1u8; 60]), seed(&[2u8; 64])];
        let generator = Generator::new(&seeds, 64);
        for iter in 0..3000 {
            let input = generator.input(iter, &mut rng(iter));
            assert!(input.bytes.len() <= 64, "{}", input.bytes.len());
        }
    }

    #[test]
    fn the_same_rng_gives_the_same_input() {
        let seeds = vec![seed(&[1u8; 60]).field(Field::new(0, Width::U8, 9))];
        let generator = Generator::new(&seeds, 128);
        for iter in 0..500 {
            let a = generator.input(iter, &mut rng(iter));
            let b = generator.input(iter, &mut rng(iter));
            assert_eq!(a.bytes, b.bytes);
            assert_eq!(a.mutations, b.mutations);
        }
    }

    #[test]
    fn random_inputs_use_one_to_four_mutations() {
        let seeds = vec![seed(&[1u8; 60])];
        let generator = Generator::new(&seeds, 128);
        let start = 1 + generator.sweep_len();
        for iter in start..start + 500 {
            let input = generator.input(iter, &mut rng(iter));
            assert!((1..=4).contains(&input.mutations.len()));
            assert!(!input.mutations.contains(&Mutation::Rechunk));
        }
    }
}
