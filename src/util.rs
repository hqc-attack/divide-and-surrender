use std::{cell::RefCell, fmt::Display};

use rand::{distributions::uniform::SampleRange, Rng};

pub fn write_hex(
    f: &mut std::fmt::Formatter,
    bytes: impl IntoIterator<Item = u8>,
) -> std::fmt::Result {
    for b in bytes.into_iter() {
        write!(f, "{:02x}", b)?;
    }
    Ok(())
}

pub fn format_hex<T: Iterator<Item = u8>>(x: T) -> FormatIter<T> {
    FormatIter(RefCell::new(Some(x)))
}

pub struct FormatIter<T: Iterator<Item = u8>>(RefCell<Option<T>>);

impl<T: Iterator<Item = u8>> Display for FormatIter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_hex(f, self.0.take().unwrap())
    }
}

pub fn sample_cww(rng: &mut impl Rng, out: &mut [u64], weight: u32) {
    out.fill(0);
    let mut w = 0;
    while w < weight {
        let pos = rng.gen_range(0..out.len() * 64);
        let block = pos / 64;
        let bit = pos % 64;
        if out[block] & (1u64 << bit) == 0 {
            out[block] |= 1u64 << bit;
            w += 1;
        }
    }
}

pub fn sample_cww_indexes<R: SampleRange<u32> + Clone>(
    rng: &mut impl Rng,
    weight: u32,
    range: R,
) -> Vec<u32> {
    let mut rv = vec![];
    while rv.len() < weight as usize {
        let pos = rng.gen_range(range.clone());
        if !rv.contains(&pos) {
            rv.push(pos);
        }
    }
    rv
}
