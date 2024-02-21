use oqs::kem::{Ciphertext, PublicKeyRef};
use rand::Rng;
use tracing::debug;

use core::arch::x86_64::__m256i;
use std::{
    simd::{u64x4, u8x32},
    time::Instant,
};

const fn ceil_divide(a: u32, b: u32) -> u32 {
    (a + b - 1) / b
}

#[derive(Debug, PartialEq, Eq)]
pub struct EncapsResult {
    pub status: oqs_sys::common::OQS_STATUS,
    pub ct: Vec<u8>,
    pub ss: Vec<u8>,
}

pub struct Poly {
    pub v: Vec<__m256i>,
}

impl PartialEq<Self> for Poly {
    fn eq(&self, other: &Self) -> bool {
        self.v.len() == other.v.len()
            && self
                .v
                .iter()
                .zip(other.v.iter())
                .all(|(a, b)| u64x4::from(*a) == u64x4::from(*b))
    }
}

impl std::fmt::Debug for Poly {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        crate::util::write_hex(f, self.v.iter().flat_map(|x| u8x32::from(*x).to_array()))
    }
}

impl Poly {
    pub fn zero(len: usize) -> Self {
        Self {
            v: vec![__m256i::from(u64x4::splat(0)); len],
        }
    }

    pub fn rand(rng: &mut impl Rng, len: usize) -> Self {
        let mut z = Self::zero(len);
        rng.fill(bytemuck::cast_slice_mut::<_, u8>(z.v.as_mut_slice()));
        z
    }
}

impl std::ops::Deref for Poly {
    type Target = Vec<__m256i>;
    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

impl std::ops::DerefMut for Poly {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.v
    }
}

#[derive(Debug)]
pub struct Pk {
    pub h: Poly,
    pub s: Poly,
}

#[derive(Debug, PartialEq)]
pub struct Sk {
    pub x: Poly,
    pub y: Poly,
    pub pk: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct Ct {
    pub u: Poly,
    pub v: Poly,
    pub d: Vec<u8>,
}

#[derive(PartialEq, Eq)]
pub enum TimingLeakage {
    RejectionSampling,
    DivisionLatency,
}

pub trait Hqc {
    const PARAM_N: u32; // Define the parameter n of the scheme
    const PARAM_N1: u32; // Define the parameter n1 of the scheme (length of Reed-Solomon code)
    const PARAM_N2: u32; // Define the parameter n2 of the scheme (length of Duplicated Reed-Muller code)
    const PARAM_N1N2: u32; // Define the length in bits of the Concatenated code
    const PARAM_OMEGA: u32; // Define the parameter omega of the scheme
    const PARAM_OMEGA_E: u32; // Define the parameter omega_e of the scheme
    const PARAM_OMEGA_R: u32; // Define the parameter omega_r of the scheme
    const PARAM_SECURITY: u32; // Define the security level corresponding to the chosen parameters
    const PARAM_DFR_EXP: u32; // Define the decryption failure rate corresponding to the chosen parameters

    const SECRET_KEY_BYTES: u32; // Define the size of the secret key in bytes
    const PUBLIC_KEY_BYTES: u32; // Define the size of the public key in bytes
    const SHARED_SECRET_BYTES: u32; // Define the size of the shared secret in bytes
    const CIPHERTEXT_BYTES: u32; // Define the size of the ciphertext in bytes

    const UTILS_REJECTION_THRESHOLD: u32; // Define the rejection threshold used to generate given weight vectors (see vector_set_random_fixed_weight function)
    const VEC_N_SIZE_BYTES: usize; // Define the size of the array used to store a PARAM_N sized vector in bytes
    const VEC_K_SIZE_BYTES: usize; // Define the size of the array used to store a PARAM_K sized vector in bytes
    const VEC_N1_SIZE_BYTES: usize; // Define the size of the array used to store a PARAM_N1 sized vector in bytes
    const VEC_N1N2_SIZE_BYTES: usize; // Define the size of the array used to store a PARAM_N1N2 sized vector in bytes

    const VEC_N_SIZE_64: usize; // Define the size of the array used to store a PARAM_N sized vector in 64 bits
    const VEC_K_SIZE_64: usize; // Define the size of the array used to store a PARAM_K sized vector in 64 bits
    const VEC_N1_SIZE_64: usize; // Define the size of the array used to store a PARAM_N1 sized vector in 64 bits
    const VEC_N2_SIZE_64: usize = ceil_divide(Self::PARAM_N2, 64) as usize;
    const VEC_N1N2_SIZE_64: usize; // Define the size of the array used to store a PARAM_N1N2 sized vector in 64 bits

    const PARAM_N_MULT: u32;
    const VEC_N_SIZE_256: usize = ceil_divide(Self::PARAM_N_MULT, 256) as usize;
    const VEC_N_256_SIZE_64: usize; // Define the size of the array of 64 bits elements used to store an array of size PARAM_N considered as elements of 256 bits
    const VEC_N1N2_256_SIZE_64: usize; // Define the size of the array of 64 bits elements used to store an array of size PARAM_N1N2 considered as elements of 256 bits

    const PARAM_DELTA: u32; // Define the parameter delta of the scheme (correcting capacity of the Reed-Solomon code)
    const PARAM_M: u32; // Define a positive integer
    const PARAM_GF_POLY: u32; // Generator polynomial of galois field GF(2^PARAM_M), represented in hexadecimial form
    const PARAM_GF_POLY_WT: u32; // Hamming weight of PARAM_GF_POLY
    const PARAM_GF_POLY_M2: u32; // Distance between the primitive polynomial first two set bits
    const PARAM_GF_MUL_ORDER: u32; // Define the size of the multiplicative group of GF(2^PARAM_M), i.e 2^PARAM_M -1
    const PARAM_K: u32; // Define the size of the information bits of the Reed-Solomon code
    const PARAM_G: u32; // Define the size of the generator polynomial of Reed-Solomon code
    const PARAM_FFT: u32; // The additive FFT takes a 2^PARAM_FFT polynomial as input
                          // We use the FFT to compute the roots of sigma, whose degree if PARAM_DELTA=24
                          // The smallest power of 2 greater than 24+1 is 32=2^5
    const RS_POLY_COEFS: &'static [u32]; // Coefficients of the generator polynomial of the Reed-Solomon code

    const RED_MASK: u64; // A mask fot the higher bits of a vector
    const SHA512_BYTES: u32; // Define the size of SHA512 output in bytes
    const SEED_BYTES: u32; // Define the size of the seed in bytes
    const SEEDEXPANDER_MAX_LENGTH: u32; // Define the seed expander max length

    const SALT_SIZE_BYTES: u64 = 0;

    const LEAKAGE: TimingLeakage;

    fn sample_message(rng: &mut impl Rng) -> Vec<u8> {
        let mut buf = vec![0u8; Self::VEC_K_SIZE_BYTES];
        rng.fill(buf.as_mut_slice());
        buf
    }

    fn sample_rm_message() -> u8 {
        rand::thread_rng().gen()
    }

    const CODE_ENCODE: unsafe extern "C" fn(v: *mut u8, m: *const u8);
    const CODE_DECODE: unsafe extern "C" fn(m: *mut u8, em: *const u8);

    fn code_encode(m: &[u8]) -> Vec<u64> {
        assert_eq!(m.len(), Self::VEC_K_SIZE_BYTES);
        let mut v = vec![0u64; Self::VEC_N1N2_256_SIZE_64];
        unsafe {
            Self::CODE_ENCODE(v.as_mut_ptr() as *mut _, m.as_ptr());
        }
        v
    }

    fn code_decode(em: &[u64]) -> Vec<u8> {
        assert_eq!(em.len(), Self::VEC_N1N2_256_SIZE_64);
        let mut m = vec![0u8; Self::VEC_K_SIZE_BYTES];
        unsafe {
            Self::CODE_DECODE(m.as_mut_ptr(), em.as_ptr() as *const _);
        }
        m
    }

    const RM_ENCODE_SINGLE: unsafe extern "C" fn(cdw: *mut u8, msg: *const u8);
    const RM_DECODE_SINGLE: unsafe extern "C" fn(msg: *mut u8, cdw: *const u8);

    fn rm_encode_single(m: u8) -> Vec<u64> {
        let mut v = vec![0u64; Self::VEC_N2_SIZE_64];
        unsafe {
            Self::RM_ENCODE_SINGLE(v.as_mut_ptr() as *mut _, &m as *const _);
        }
        v
    }

    fn rm_decode_single(em: &[u64]) -> u8 {
        assert_eq!(em.len(), Self::VEC_N2_SIZE_64);
        let mut m = 0;
        unsafe {
            Self::RM_DECODE_SINGLE(&mut m as *mut _, em.as_ptr() as *const _);
        }
        m
    }

    const ENCAPS_CHOSEN_INPUTS: unsafe extern "C" fn(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        m: *const u8,
        u: *const u8,
        r2: *const u8,
        e: *const u8,
    ) -> oqs_sys::common::OQS_STATUS = encaps_chosen_inputs_unimplemented;

    const ENCAPS_CHOSEN_INPUTS_WITH_SALT: unsafe extern "C" fn(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        m: *const u8,
        u: *const u8,
        r2: *const u8,
        e: *const u8,
        salt: *const u8,
    ) -> oqs_sys::common::OQS_STATUS = encaps_chosen_inputs_with_salt_unimplemented;

    fn encaps_chosen_inputs(
        pk: &[u8],
        m: &[u8],
        u: &[u8],
        r2: &[u8],
        e: &[u8],
        salt: Option<&[u8]>,
    ) -> EncapsResult {
        assert_eq!(pk.len(), Self::PUBLIC_KEY_BYTES as usize);
        assert_eq!(m.len(), { Self::VEC_K_SIZE_BYTES });
        let mut ct = vec![0u8; Self::CIPHERTEXT_BYTES as usize];
        let mut ss = vec![0u8; Self::SHARED_SECRET_BYTES as usize];

        let status = match salt {
            Some(salt) => unsafe {
                Self::ENCAPS_CHOSEN_INPUTS_WITH_SALT(
                    ct.as_mut_ptr(),
                    ss.as_mut_ptr(),
                    pk.as_ptr(),
                    m.as_ptr(),
                    u.as_ptr(),
                    r2.as_ptr(),
                    e.as_ptr(),
                    salt.as_ptr(),
                )
            },
            None => unsafe {
                Self::ENCAPS_CHOSEN_INPUTS(
                    ct.as_mut_ptr(),
                    ss.as_mut_ptr(),
                    pk.as_ptr(),
                    m.as_ptr(),
                    u.as_ptr(),
                    r2.as_ptr(),
                    e.as_ptr(),
                )
            },
        };
        EncapsResult { status, ct, ss }
    }

    const ALGORITHM: oqs::kem::Algorithm;

    fn oqs() -> oqs::kem::Kem {
        oqs::kem::Kem::new(Self::ALGORITHM).unwrap()
    }

    const PUBLIC_KEY_FROM_STRING: unsafe extern "C" fn(h: *mut u64, s: *mut u64, pk: *const u8);

    fn public_key_from_string(pk: &[u8]) -> Pk {
        assert_eq!(pk.len(), Self::PUBLIC_KEY_BYTES as usize);
        let mut h = Poly::zero(Self::VEC_N_SIZE_256);
        let mut s = Poly::zero(Self::VEC_N_SIZE_256);
        unsafe {
            Self::PUBLIC_KEY_FROM_STRING(
                h.as_mut_ptr() as *mut _,
                s.as_mut_ptr() as *mut _,
                pk.as_ptr(),
            );
        }
        Pk { h, s }
    }

    const SECRET_KEY_FROM_STRING: unsafe extern "C" fn(
        x: *mut u64,
        y: *mut u64,
        pk: *mut u8,
        sk: *const u8,
    );

    fn secret_key_from_string(sk: &[u8]) -> Sk {
        assert_eq!(sk.len(), Self::SECRET_KEY_BYTES as usize);
        let mut x = Poly::zero(Self::VEC_N_SIZE_256);
        let mut y = Poly::zero(Self::VEC_N_SIZE_256);
        let mut pk = vec![0u8; Self::PUBLIC_KEY_BYTES as usize];
        unsafe {
            Self::SECRET_KEY_FROM_STRING(
                x.as_mut_ptr() as *mut _,
                y.as_mut_ptr() as *mut _,
                pk.as_mut_ptr(),
                sk.as_ptr(),
            );
        }
        Sk { x, y, pk }
    }

    const CIPHERTEXT_FROM_STRING: unsafe extern "C" fn(
        u: *mut u64,
        v: *mut u64,
        d: *mut u8,
        ct: *const u8,
    );

    fn ciphertext_from_string(ct: &[u8]) -> Ct {
        let mut u = Poly::zero(Self::VEC_N_SIZE_256);
        let mut v = Poly::zero(Self::VEC_N_SIZE_256);
        let d_size = match Self::LEAKAGE {
            TimingLeakage::DivisionLatency => Self::SALT_SIZE_BYTES as usize,
            TimingLeakage::RejectionSampling => Self::SHA512_BYTES as usize,
        };
        let mut d = vec![0u8; d_size];
        unsafe {
            Self::CIPHERTEXT_FROM_STRING(
                u.as_mut_ptr() as *mut _,
                v.as_mut_ptr() as *mut _,
                d.as_mut_ptr(),
                ct.as_ptr(),
            );
        }
        Ct { u, v, d }
    }

    fn ciphertext_to_string(ct: &Ct) -> Ciphertext {
        let mut v = Vec::<u8>::new();
        v.extend(&bytemuck::cast_slice(ct.u.as_slice())[..Self::VEC_N_SIZE_BYTES]);
        v.extend(&bytemuck::cast_slice(ct.v.as_slice())[..Self::VEC_N1N2_SIZE_BYTES]);
        let d_size = match Self::LEAKAGE {
            TimingLeakage::DivisionLatency => Self::SALT_SIZE_BYTES as usize,
            TimingLeakage::RejectionSampling => Self::SHA512_BYTES as usize,
        };
        v.extend(&bytemuck::cast_slice(ct.d.as_slice())[..d_size]);
        Ciphertext { bytes: v }
    }

    // needs aligned vectors!
    const VECT_MUL: unsafe extern "C" fn(o: *mut u64, a1: *const u8, a1: *const u8);

    fn vect_mul(a1: &Poly, a2: &Poly) -> Poly {
        assert_eq!(a1.len(), Self::VEC_N_SIZE_256);
        assert_eq!(a2.len(), Self::VEC_N_SIZE_256);
        let mut o = Poly::zero(Self::VEC_N_SIZE_256);
        unsafe {
            Self::VECT_MUL(
                o.as_mut_ptr() as *mut _,
                a1.as_ptr() as *const _,
                a2.as_ptr() as *const _,
            );
        }
        o
    }

    const VECT_ADD: unsafe extern "C" fn(O: *mut u64, v1: *const u64, v2: *const u64, u32);

    fn vect_add(v1: &Poly, v2: &Poly) -> Poly {
        assert_eq!(v1.len(), Self::VEC_N_SIZE_256);
        assert_eq!(v2.len(), Self::VEC_N_SIZE_256);
        let mut o = Poly::zero(Self::VEC_N_SIZE_256);
        unsafe {
            Self::VECT_ADD(
                o.as_mut_ptr() as *mut _,
                v1.as_ptr() as *const _,
                v2.as_ptr() as *const _,
                Self::VEC_N_SIZE_64 as u32,
            );
        }
        o
    }

    const NUM_SEEDEXPANSIONS: unsafe extern "C" fn(m: *const u8) -> u32;

    fn num_seedexpansions(m: &[u8]) -> u32 {
        assert_eq!(m.len(), Self::VEC_K_SIZE_BYTES);
        unsafe { Self::NUM_SEEDEXPANSIONS(m.as_ptr()) }
    }

    fn find_high_seedexpansion_message(rng: &mut impl Rng) -> Vec<u8> {
        loop {
            let m = Self::sample_message(rng);
            if Self::num_seedexpansions(&m) >= 6 || Self::LEAKAGE == TimingLeakage::DivisionLatency
            {
                return m;
            }
        }
    }

    fn find_low_division_latency_salt(rng: &mut impl Rng, pk: PublicKeyRef, msg: &[u8]) -> Vec<u8> {
        let start = Instant::now();
        let mut lowest_salt = None;
        let mut lowest_latency = u32::MAX;
        let mut latencies = vec![];
        let mut its = 0;
        for _ in 0..5000 {
            let mut salt = vec![0u8; Self::VEC_K_SIZE_BYTES];
            rng.fill(salt.as_mut_slice());
            let latency = Self::division_latency(msg, pk.as_ref(), &salt);
            its += 1;
            if latency < lowest_latency {
                lowest_salt = Some(salt);
                lowest_latency = latency;
            }
            latencies.push(latency);
        }
        latencies.sort_unstable();
        let median_latency = latencies[latencies.len() / 2];
        loop {
            let diff = median_latency - lowest_latency;
            if diff >= 55 {
                break;
            }
            let mut salt = vec![0u8; Self::VEC_K_SIZE_BYTES];
            rng.fill(salt.as_mut_slice());
            let latency = Self::division_latency(msg, pk.as_ref(), &salt);
            its += 1;
            if latency < lowest_latency {
                debug!(
                    "New lower latency: {latency} with diff {}",
                    median_latency - lowest_latency
                );
                lowest_salt = Some(salt);
                lowest_latency = latency;
            }
        }
        let diff = median_latency - lowest_latency;
        let dur = start.elapsed();
        debug!("using salt with division latency {lowest_latency} (median is {median_latency} with diff {diff}). Found after 2^{:.02} iterations in {dur:.02?} ({:.02} iter/s).", (its as f64).log2(), its as f64 / dur.as_secs_f64());
        lowest_salt.unwrap()
    }

    const DIVISION_LATENCY: unsafe extern "C" fn(
        m: *const u8,
        pk: *const u8,
        salt: *const u8,
    ) -> u32 = division_latency_unimplemented;

    fn division_latency(m: &[u8], pk: &[u8], salt: &[u8]) -> u32 {
        assert!(salt.len() >= Self::SALT_SIZE_BYTES as usize);
        assert!(m.len() >= Self::VEC_K_SIZE_BYTES);
        assert!(pk.len() >= Self::PUBLIC_KEY_BYTES as usize);

        unsafe { Self::DIVISION_LATENCY(m.as_ptr(), pk.as_ptr(), salt.as_ptr()) }
    }

    // OQS_API void OQS_KEM_hqc_r4_192_AVX2_shake_prng_init(uint8_t *entropy_input, uint8_t *personalization_string, uint32_t enlen, uint32_t perlen) {
    const INIT_SEED: unsafe extern "C" fn(
        entropy_input: *mut u8,
        personalization_string: *mut u8,
        enlen: u32,
        perlen: u32,
    ) = init_seed_unimplemented as _;

    fn init_seed(seed: u64) {
        let mut s = vec![0u8; 48];
        s[0..8].copy_from_slice(seed.to_be_bytes().as_slice());
        unsafe {
            Self::INIT_SEED(s.as_mut_ptr(), std::ptr::null_mut(), s.len() as u32, 0);
        }
    }
}

unsafe extern "C" fn init_seed_unimplemented(
    _entropy_input: *mut u8,
    _personalization_string: *mut u8,
    _enlen: u32,
    _perlen: u32,
) {
    unimplemented!("init_seed");
}

unsafe extern "C" fn division_latency_unimplemented(
    _m: *const u8,
    _pk: *const u8,
    _salt: *const u8,
) -> u32 {
    unimplemented!("division_latency");
}

unsafe extern "C" fn encaps_chosen_inputs_unimplemented(
    _ct: *mut u8,
    _ss: *mut u8,
    _pk: *const u8,
    _m: *const u8,
    _u: *const u8,
    _r2: *const u8,
    _e: *const u8,
) -> oqs_sys::common::OQS_STATUS {
    unimplemented!("encaps chosen inputs")
}

unsafe extern "C" fn encaps_chosen_inputs_with_salt_unimplemented(
    _ct: *mut u8,
    _ss: *mut u8,
    _pk: *const u8,
    _m: *const u8,
    _u: *const u8,
    _r2: *const u8,
    _e: *const u8,
    _salt: *const u8,
) -> oqs_sys::common::OQS_STATUS {
    unimplemented!("encaps chosen inputs with salt")
}

pub struct Hqc128;
pub struct Hqc192;
pub struct Hqc256;

impl Hqc for Hqc128 {
    const LEAKAGE: TimingLeakage = TimingLeakage::RejectionSampling;
    const PARAM_N: u32 = 17669;
    const PARAM_N1: u32 = 46;
    const PARAM_N2: u32 = 384;
    const PARAM_N1N2: u32 = 17664;
    const PARAM_OMEGA: u32 = 66;
    const PARAM_OMEGA_E: u32 = 75;
    const PARAM_OMEGA_R: u32 = 75;
    const PARAM_SECURITY: u32 = 128;
    const PARAM_DFR_EXP: u32 = 128;

    const SECRET_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_128_length_secret_key;
    const PUBLIC_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_128_length_public_key;
    const SHARED_SECRET_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_128_length_shared_secret;
    const CIPHERTEXT_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_128_length_ciphertext;

    const UTILS_REJECTION_THRESHOLD: u32 = 16767881;
    const VEC_N_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N, 8) as usize;
    const VEC_K_SIZE_BYTES: usize = Self::PARAM_K as usize;
    const VEC_N1_SIZE_BYTES: usize = Self::PARAM_N1 as usize;
    const VEC_N1N2_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N1N2, 8) as usize;

    const VEC_N_SIZE_64: usize = ceil_divide(Self::PARAM_N, 64) as usize;
    const VEC_K_SIZE_64: usize = ceil_divide(Self::PARAM_K, 8) as usize;
    const VEC_N1_SIZE_64: usize = ceil_divide(Self::PARAM_N1, 8) as usize;
    const VEC_N1N2_SIZE_64: usize = ceil_divide(Self::PARAM_N1N2, 64) as usize;

    const PARAM_N_MULT: u32 = 9 * 256 * ceil_divide(ceil_divide(Self::PARAM_N, 9), 256);
    const VEC_N_256_SIZE_64: usize = (Self::PARAM_N_MULT / 64) as usize;
    const VEC_N1N2_256_SIZE_64: usize = (ceil_divide(Self::PARAM_N1N2, 256) << 2) as usize;

    const PARAM_DELTA: u32 = 15;
    const PARAM_M: u32 = 8;
    const PARAM_GF_POLY: u32 = 0x11D;
    const PARAM_GF_POLY_WT: u32 = 5;
    const PARAM_GF_POLY_M2: u32 = 4;
    const PARAM_GF_MUL_ORDER: u32 = 255;
    const PARAM_K: u32 = 16;
    const PARAM_G: u32 = 31;
    const PARAM_FFT: u32 = 5;
    const RS_POLY_COEFS: &'static [u32] = &[
        89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67,
        118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
    ];

    const RED_MASK: u64 = 0x1f;
    const SHA512_BYTES: u32 = 64;
    const SEED_BYTES: u32 = 40;
    const SEEDEXPANDER_MAX_LENGTH: u32 = 4294967295;

    const CODE_ENCODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_128_code_encode;
    const CODE_DECODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_128_code_decode;

    const RM_ENCODE_SINGLE: unsafe extern "C" fn(cdw: *mut u8, msg: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_128_reed_muller_encode_single;
    const RM_DECODE_SINGLE: unsafe extern "C" fn(msg: *mut u8, cdw: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_128_reed_muller_decode_single;

    const ENCAPS_CHOSEN_INPUTS: unsafe extern "C" fn(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        m: *const u8,
        r1: *const u8,
        r2: *const u8,
        e: *const u8,
    ) -> oqs_sys::common::OQS_STATUS = oqs_sys::kem::OQS_KEM_hqc_128_encaps_chosen_inputs;

    const PUBLIC_KEY_FROM_STRING: unsafe extern "C" fn(h: *mut u64, s: *mut u64, pk: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_128_public_key_from_string;

    const SECRET_KEY_FROM_STRING: unsafe extern "C" fn(
        x: *mut u64,
        y: *mut u64,
        pk: *mut u8,
        sk: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_128_secret_key_from_string;

    const VECT_MUL: unsafe extern "C" fn(o: *mut u64, a1: *const u8, a1: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_128_vect_mul;
    const VECT_ADD: unsafe extern "C" fn(O: *mut u64, v1: *const u64, v2: *const u64, u32) =
        oqs_sys::kem::OQS_KEM_hqc_128_vect_add;

    const NUM_SEEDEXPANSIONS: unsafe extern "C" fn(m: *const u8) -> u32 =
        oqs_sys::kem::OQS_KEM_hqc_128_num_seedexpansions;
    const CIPHERTEXT_FROM_STRING: unsafe extern "C" fn(
        u: *mut u64,
        v: *mut u64,
        d: *mut u8,
        ct: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_128_ciphertext_from_string;

    const ALGORITHM: oqs::kem::Algorithm = oqs::kem::Algorithm::Hqc128;
}

impl Hqc for Hqc192 {
    const LEAKAGE: TimingLeakage = TimingLeakage::RejectionSampling;
    const PARAM_N: u32 = 35851;
    const PARAM_N1: u32 = 56;
    const PARAM_N2: u32 = 640;
    const PARAM_N1N2: u32 = 35840;
    const PARAM_OMEGA: u32 = 100;
    const PARAM_OMEGA_E: u32 = 114;
    const PARAM_OMEGA_R: u32 = 114;
    const PARAM_SECURITY: u32 = 192;
    const PARAM_DFR_EXP: u32 = 192;

    const SECRET_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_192_length_secret_key;
    const PUBLIC_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_192_length_public_key;
    const SHARED_SECRET_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_192_length_shared_secret;
    const CIPHERTEXT_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_192_length_ciphertext;

    const UTILS_REJECTION_THRESHOLD: u32 = 16742417;
    const VEC_N_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N, 8) as usize;
    const VEC_K_SIZE_BYTES: usize = Self::PARAM_K as usize;
    const VEC_N1_SIZE_BYTES: usize = Self::PARAM_N1 as usize;
    const VEC_N1N2_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N1N2, 8) as usize;

    const VEC_N_SIZE_64: usize = ceil_divide(Self::PARAM_N, 64) as usize;
    const VEC_K_SIZE_64: usize = ceil_divide(Self::PARAM_K, 8) as usize;
    const VEC_N1_SIZE_64: usize = ceil_divide(Self::PARAM_N1, 8) as usize;
    const VEC_N1N2_SIZE_64: usize = ceil_divide(Self::PARAM_N1N2, 64) as usize;

    const PARAM_N_MULT: u32 = 9 * 256 * ceil_divide(ceil_divide(Self::PARAM_N, 9), 256);
    const VEC_N_256_SIZE_64: usize = (Self::PARAM_N_MULT / 64) as usize;
    const VEC_N1N2_256_SIZE_64: usize = (ceil_divide(Self::PARAM_N1N2, 256) << 2) as usize;

    const PARAM_DELTA: u32 = 16;
    const PARAM_M: u32 = 8;
    const PARAM_GF_POLY: u32 = 0x11D;
    const PARAM_GF_POLY_WT: u32 = 5;
    const PARAM_GF_POLY_M2: u32 = 4;
    const PARAM_GF_MUL_ORDER: u32 = 255;
    const PARAM_K: u32 = 24;
    const PARAM_G: u32 = 33;
    const PARAM_FFT: u32 = 5;
    const RS_POLY_COEFS: &'static [u32] = &[
        45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
        238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
    ];

    const RED_MASK: u64 = 0x7ff;
    const SHA512_BYTES: u32 = 64;
    const SEED_BYTES: u32 = 40;
    const SEEDEXPANDER_MAX_LENGTH: u32 = 4294967295;

    const CODE_ENCODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_192_code_encode;
    const CODE_DECODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_192_code_decode;

    const RM_ENCODE_SINGLE: unsafe extern "C" fn(cdw: *mut u8, msg: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_192_reed_muller_encode_single;
    const RM_DECODE_SINGLE: unsafe extern "C" fn(msg: *mut u8, cdw: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_192_reed_muller_decode_single;

    const ENCAPS_CHOSEN_INPUTS: unsafe extern "C" fn(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        m: *const u8,
        u: *const u8,
        r2: *const u8,
        e: *const u8,
    ) -> oqs_sys::common::OQS_STATUS = oqs_sys::kem::OQS_KEM_hqc_192_encaps_chosen_inputs;

    const PUBLIC_KEY_FROM_STRING: unsafe extern "C" fn(h: *mut u64, s: *mut u64, pk: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_192_public_key_from_string;
    const SECRET_KEY_FROM_STRING: unsafe extern "C" fn(
        x: *mut u64,
        y: *mut u64,
        pk: *mut u8,
        sk: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_192_secret_key_from_string;

    const VECT_MUL: unsafe extern "C" fn(o: *mut u64, a1: *const u8, a1: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_192_vect_mul;
    const VECT_ADD: unsafe extern "C" fn(O: *mut u64, v1: *const u64, v2: *const u64, u32) =
        oqs_sys::kem::OQS_KEM_hqc_192_vect_add;

    const NUM_SEEDEXPANSIONS: unsafe extern "C" fn(m: *const u8) -> u32 =
        oqs_sys::kem::OQS_KEM_hqc_192_num_seedexpansions;
    const CIPHERTEXT_FROM_STRING: unsafe extern "C" fn(
        u: *mut u64,
        v: *mut u64,
        d: *mut u8,
        ct: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_192_ciphertext_from_string;

    const ALGORITHM: oqs::kem::Algorithm = oqs::kem::Algorithm::Hqc192;
}

impl Hqc for Hqc256 {
    const LEAKAGE: TimingLeakage = TimingLeakage::RejectionSampling;
    const PARAM_N: u32 = 57637;
    const PARAM_N1: u32 = 90;
    const PARAM_N2: u32 = 640;
    const PARAM_N1N2: u32 = 57600;
    const PARAM_OMEGA: u32 = 131;
    const PARAM_OMEGA_E: u32 = 149;
    const PARAM_OMEGA_R: u32 = 149;
    const PARAM_SECURITY: u32 = 256;
    const PARAM_DFR_EXP: u32 = 256;

    const SECRET_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_256_length_secret_key;
    const PUBLIC_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_256_length_public_key;
    const SHARED_SECRET_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_256_length_shared_secret;
    const CIPHERTEXT_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_256_length_ciphertext;

    const UTILS_REJECTION_THRESHOLD: u32 = 16772367;
    const VEC_N_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N, 8) as usize;
    const VEC_K_SIZE_BYTES: usize = Self::PARAM_K as usize;
    const VEC_N1_SIZE_BYTES: usize = Self::PARAM_N1 as usize;
    const VEC_N1N2_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N1N2, 8) as usize;

    const VEC_N_SIZE_64: usize = ceil_divide(Self::PARAM_N, 64) as usize;
    const VEC_K_SIZE_64: usize = ceil_divide(Self::PARAM_K, 8) as usize;
    const VEC_N1_SIZE_64: usize = ceil_divide(Self::PARAM_N1, 8) as usize;
    const VEC_N1N2_SIZE_64: usize = ceil_divide(Self::PARAM_N1N2, 64) as usize;

    const PARAM_N_MULT: u32 = 9 * 256 * ceil_divide(ceil_divide(Self::PARAM_N, 9), 256);
    const VEC_N_256_SIZE_64: usize = (Self::PARAM_N_MULT / 64) as usize;
    const VEC_N1N2_256_SIZE_64: usize = (ceil_divide(Self::PARAM_N1N2, 256) << 2) as usize;

    const PARAM_DELTA: u32 = 29;
    const PARAM_M: u32 = 8;
    const PARAM_GF_POLY: u32 = 0x11D;
    const PARAM_GF_POLY_WT: u32 = 5;
    const PARAM_GF_POLY_M2: u32 = 4;
    const PARAM_GF_MUL_ORDER: u32 = 255;
    const PARAM_K: u32 = 32;
    const PARAM_G: u32 = 59;
    const PARAM_FFT: u32 = 5;
    const RS_POLY_COEFS: &'static [u32] = &[
        49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71,
        201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4,
        246, 191, 144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
    ];

    const RED_MASK: u64 = 0x1fffffffff;
    const SHA512_BYTES: u32 = 64;
    const SEED_BYTES: u32 = 40;
    const SEEDEXPANDER_MAX_LENGTH: u32 = 4294967295;

    const CODE_ENCODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_256_code_encode;
    const CODE_DECODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_256_code_decode;

    const RM_ENCODE_SINGLE: unsafe extern "C" fn(cdw: *mut u8, msg: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_256_reed_muller_encode_single;
    const RM_DECODE_SINGLE: unsafe extern "C" fn(msg: *mut u8, cdw: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_256_reed_muller_decode_single;

    const ENCAPS_CHOSEN_INPUTS: unsafe extern "C" fn(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        m: *const u8,
        u: *const u8,
        r2: *const u8,
        e: *const u8,
    ) -> oqs_sys::common::OQS_STATUS = oqs_sys::kem::OQS_KEM_hqc_256_encaps_chosen_inputs;

    const PUBLIC_KEY_FROM_STRING: unsafe extern "C" fn(h: *mut u64, s: *mut u64, pk: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_256_public_key_from_string;
    const SECRET_KEY_FROM_STRING: unsafe extern "C" fn(
        x: *mut u64,
        y: *mut u64,
        pk: *mut u8,
        sk: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_256_secret_key_from_string;

    const VECT_MUL: unsafe extern "C" fn(o: *mut u64, a1: *const u8, a1: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_256_vect_mul;
    const VECT_ADD: unsafe extern "C" fn(O: *mut u64, v1: *const u64, v2: *const u64, u32) =
        oqs_sys::kem::OQS_KEM_hqc_256_vect_add;

    const NUM_SEEDEXPANSIONS: unsafe extern "C" fn(m: *const u8) -> u32 =
        oqs_sys::kem::OQS_KEM_hqc_256_num_seedexpansions;
    const CIPHERTEXT_FROM_STRING: unsafe extern "C" fn(
        u: *mut u64,
        v: *mut u64,
        d: *mut u8,
        ct: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_256_ciphertext_from_string;

    const ALGORITHM: oqs::kem::Algorithm = oqs::kem::Algorithm::Hqc256;
}

pub struct HqcR4128;
pub struct HqcR4192;
pub struct HqcR4256;

impl Hqc for HqcR4128 {
    const LEAKAGE: TimingLeakage = TimingLeakage::DivisionLatency;
    const PARAM_N: u32 = 17669;
    const PARAM_N1: u32 = 46;
    const PARAM_N2: u32 = 384;
    const PARAM_N1N2: u32 = 17664;
    const PARAM_OMEGA: u32 = 66;
    const PARAM_OMEGA_E: u32 = 75;
    const PARAM_OMEGA_R: u32 = 75;
    const PARAM_SECURITY: u32 = 128;
    const PARAM_DFR_EXP: u32 = 128;

    const SECRET_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_128_length_secret_key;
    const PUBLIC_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_128_length_public_key;
    const SHARED_SECRET_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_128_length_shared_secret;
    const CIPHERTEXT_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_128_length_ciphertext;

    const UTILS_REJECTION_THRESHOLD: u32 = 16767881;
    const VEC_N_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N, 8) as usize;
    const VEC_K_SIZE_BYTES: usize = Self::PARAM_K as usize;
    const VEC_N1_SIZE_BYTES: usize = Self::PARAM_N1 as usize;
    const VEC_N1N2_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N1N2, 8) as usize;

    const VEC_N_SIZE_64: usize = ceil_divide(Self::PARAM_N, 64) as usize;
    const VEC_K_SIZE_64: usize = ceil_divide(Self::PARAM_K, 8) as usize;
    const VEC_N1_SIZE_64: usize = ceil_divide(Self::PARAM_N1, 8) as usize;
    const VEC_N1N2_SIZE_64: usize = ceil_divide(Self::PARAM_N1N2, 64) as usize;

    const PARAM_N_MULT: u32 = 9 * 256 * ceil_divide(ceil_divide(Self::PARAM_N, 9), 256);
    const VEC_N_256_SIZE_64: usize = (Self::PARAM_N_MULT / 64) as usize;
    const VEC_N1N2_256_SIZE_64: usize = (ceil_divide(Self::PARAM_N1N2, 256) << 2) as usize;

    const PARAM_DELTA: u32 = 15;
    const PARAM_M: u32 = 8;
    const PARAM_GF_POLY: u32 = 0x11D;
    const PARAM_GF_POLY_WT: u32 = 5;
    const PARAM_GF_POLY_M2: u32 = 4;
    const PARAM_GF_MUL_ORDER: u32 = 255;
    const PARAM_K: u32 = 16;
    const PARAM_G: u32 = 31;
    const PARAM_FFT: u32 = 5;
    const RS_POLY_COEFS: &'static [u32] = &[
        89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67,
        118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
    ];

    const RED_MASK: u64 = 0x1f;
    const SHA512_BYTES: u32 = 64;
    const SEED_BYTES: u32 = 40;
    const SEEDEXPANDER_MAX_LENGTH: u32 = 4294967295;
    const SALT_SIZE_BYTES: u64 = 16;

    const CODE_ENCODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_128_code_encode;
    const CODE_DECODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_128_code_decode;

    const RM_ENCODE_SINGLE: unsafe extern "C" fn(cdw: *mut u8, msg: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_128_reed_muller_encode_single;
    const RM_DECODE_SINGLE: unsafe extern "C" fn(msg: *mut u8, cdw: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_128_reed_muller_decode_single;

    const ENCAPS_CHOSEN_INPUTS_WITH_SALT: unsafe extern "C" fn(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        m: *const u8,
        u: *const u8,
        r2: *const u8,
        e: *const u8,
        salt: *const u8,
    ) -> oqs_sys::common::OQS_STATUS = oqs_sys::kem::OQS_KEM_hqc_r4_128_encaps_chosen_inputs;

    const PUBLIC_KEY_FROM_STRING: unsafe extern "C" fn(h: *mut u64, s: *mut u64, pk: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_128_public_key_from_string;

    const SECRET_KEY_FROM_STRING: unsafe extern "C" fn(
        x: *mut u64,
        y: *mut u64,
        pk: *mut u8,
        sk: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_r4_128_secret_key_from_string;

    const VECT_MUL: unsafe extern "C" fn(o: *mut u64, a1: *const u8, a1: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_128_vect_mul;
    const VECT_ADD: unsafe extern "C" fn(O: *mut u64, v1: *const u64, v2: *const u64, u32) =
        oqs_sys::kem::OQS_KEM_hqc_r4_128_vect_add;

    const NUM_SEEDEXPANSIONS: unsafe extern "C" fn(m: *const u8) -> u32 =
        oqs_sys::kem::OQS_KEM_hqc_r4_128_num_seedexpansions;
    const DIVISION_LATENCY: unsafe extern "C" fn(
        m: *const u8,
        pk: *const u8,
        salt: *const u8,
    ) -> u32 = oqs_sys::kem::OQS_KEM_hqc_r4_128_division_latency;
    const CIPHERTEXT_FROM_STRING: unsafe extern "C" fn(
        u: *mut u64,
        v: *mut u64,
        d: *mut u8,
        ct: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_r4_128_ciphertext_from_string;

    const ALGORITHM: oqs::kem::Algorithm = oqs::kem::Algorithm::HqcR4128;

    const INIT_SEED: unsafe extern "C" fn(
        entropy_input: *mut u8,
        personalization_string: *mut u8,
        enlen: u32,
        perlen: u32,
    ) = oqs_sys::kem::OQS_KEM_hqc_r4_128_AVX2_shake_prng_init;
}

impl Hqc for HqcR4192 {
    const LEAKAGE: TimingLeakage = TimingLeakage::DivisionLatency;
    const PARAM_N: u32 = 35851;
    const PARAM_N1: u32 = 56;
    const PARAM_N2: u32 = 640;
    const PARAM_N1N2: u32 = 35840;
    const PARAM_OMEGA: u32 = 100;
    const PARAM_OMEGA_E: u32 = 114;
    const PARAM_OMEGA_R: u32 = 114;
    const PARAM_SECURITY: u32 = 192;
    const PARAM_DFR_EXP: u32 = 192;

    const SECRET_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_192_length_secret_key;
    const PUBLIC_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_192_length_public_key;
    const SHARED_SECRET_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_192_length_shared_secret;
    const CIPHERTEXT_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_192_length_ciphertext;

    const UTILS_REJECTION_THRESHOLD: u32 = 16742417;
    const VEC_N_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N, 8) as usize;
    const VEC_K_SIZE_BYTES: usize = Self::PARAM_K as usize;
    const VEC_N1_SIZE_BYTES: usize = Self::PARAM_N1 as usize;
    const VEC_N1N2_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N1N2, 8) as usize;

    const VEC_N_SIZE_64: usize = ceil_divide(Self::PARAM_N, 64) as usize;
    const VEC_K_SIZE_64: usize = ceil_divide(Self::PARAM_K, 8) as usize;
    const VEC_N1_SIZE_64: usize = ceil_divide(Self::PARAM_N1, 8) as usize;
    const VEC_N1N2_SIZE_64: usize = ceil_divide(Self::PARAM_N1N2, 64) as usize;

    const PARAM_N_MULT: u32 = 9 * 256 * ceil_divide(ceil_divide(Self::PARAM_N, 9), 256);
    const VEC_N_256_SIZE_64: usize = (Self::PARAM_N_MULT / 64) as usize;
    const VEC_N1N2_256_SIZE_64: usize = (ceil_divide(Self::PARAM_N1N2, 256) << 2) as usize;

    const PARAM_DELTA: u32 = 16;
    const PARAM_M: u32 = 8;
    const PARAM_GF_POLY: u32 = 0x11D;
    const PARAM_GF_POLY_WT: u32 = 5;
    const PARAM_GF_POLY_M2: u32 = 4;
    const PARAM_GF_MUL_ORDER: u32 = 255;
    const PARAM_K: u32 = 24;
    const PARAM_G: u32 = 33;
    const PARAM_FFT: u32 = 5;
    const RS_POLY_COEFS: &'static [u32] = &[
        45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
        238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
    ];

    const RED_MASK: u64 = 0x7ff;
    const SHA512_BYTES: u32 = 64;
    const SEED_BYTES: u32 = 40;
    const SEEDEXPANDER_MAX_LENGTH: u32 = 4294967295;
    const SALT_SIZE_BYTES: u64 = 16;

    const CODE_ENCODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_192_code_encode;
    const CODE_DECODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_192_code_decode;

    const RM_ENCODE_SINGLE: unsafe extern "C" fn(cdw: *mut u8, msg: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_192_reed_muller_encode_single;
    const RM_DECODE_SINGLE: unsafe extern "C" fn(msg: *mut u8, cdw: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_192_reed_muller_decode_single;

    const ENCAPS_CHOSEN_INPUTS_WITH_SALT: unsafe extern "C" fn(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        m: *const u8,
        u: *const u8,
        r2: *const u8,
        e: *const u8,
        salt: *const u8,
    ) -> oqs_sys::common::OQS_STATUS = oqs_sys::kem::OQS_KEM_hqc_r4_192_encaps_chosen_inputs;

    const PUBLIC_KEY_FROM_STRING: unsafe extern "C" fn(h: *mut u64, s: *mut u64, pk: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_192_public_key_from_string;
    const SECRET_KEY_FROM_STRING: unsafe extern "C" fn(
        x: *mut u64,
        y: *mut u64,
        pk: *mut u8,
        sk: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_r4_192_secret_key_from_string;

    const VECT_MUL: unsafe extern "C" fn(o: *mut u64, a1: *const u8, a1: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_192_vect_mul;
    const VECT_ADD: unsafe extern "C" fn(O: *mut u64, v1: *const u64, v2: *const u64, u32) =
        oqs_sys::kem::OQS_KEM_hqc_r4_192_vect_add;

    const NUM_SEEDEXPANSIONS: unsafe extern "C" fn(m: *const u8) -> u32 =
        oqs_sys::kem::OQS_KEM_hqc_r4_192_num_seedexpansions;
    const DIVISION_LATENCY: unsafe extern "C" fn(
        m: *const u8,
        pk: *const u8,
        salt: *const u8,
    ) -> u32 = oqs_sys::kem::OQS_KEM_hqc_r4_192_division_latency;
    const CIPHERTEXT_FROM_STRING: unsafe extern "C" fn(
        u: *mut u64,
        v: *mut u64,
        d: *mut u8,
        ct: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_r4_192_ciphertext_from_string;

    const ALGORITHM: oqs::kem::Algorithm = oqs::kem::Algorithm::HqcR4192;

    const INIT_SEED: unsafe extern "C" fn(
        entropy_input: *mut u8,
        personalization_string: *mut u8,
        enlen: u32,
        perlen: u32,
    ) = oqs_sys::kem::OQS_KEM_hqc_r4_192_AVX2_shake_prng_init;
}

impl Hqc for HqcR4256 {
    const LEAKAGE: TimingLeakage = TimingLeakage::DivisionLatency;
    const PARAM_N: u32 = 57637;
    const PARAM_N1: u32 = 90;
    const PARAM_N2: u32 = 640;
    const PARAM_N1N2: u32 = 57600;
    const PARAM_OMEGA: u32 = 131;
    const PARAM_OMEGA_E: u32 = 149;
    const PARAM_OMEGA_R: u32 = 149;
    const PARAM_SECURITY: u32 = 256;
    const PARAM_DFR_EXP: u32 = 256;

    const SECRET_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_256_length_secret_key;
    const PUBLIC_KEY_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_256_length_public_key;
    const SHARED_SECRET_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_256_length_shared_secret;
    const CIPHERTEXT_BYTES: u32 = oqs_sys::kem::OQS_KEM_hqc_r4_256_length_ciphertext;

    const UTILS_REJECTION_THRESHOLD: u32 = 16772367;
    const VEC_N_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N, 8) as usize;
    const VEC_K_SIZE_BYTES: usize = Self::PARAM_K as usize;
    const VEC_N1_SIZE_BYTES: usize = Self::PARAM_N1 as usize;
    const VEC_N1N2_SIZE_BYTES: usize = ceil_divide(Self::PARAM_N1N2, 8) as usize;

    const VEC_N_SIZE_64: usize = ceil_divide(Self::PARAM_N, 64) as usize;
    const VEC_K_SIZE_64: usize = ceil_divide(Self::PARAM_K, 8) as usize;
    const VEC_N1_SIZE_64: usize = ceil_divide(Self::PARAM_N1, 8) as usize;
    const VEC_N1N2_SIZE_64: usize = ceil_divide(Self::PARAM_N1N2, 64) as usize;

    const PARAM_N_MULT: u32 = 9 * 256 * ceil_divide(ceil_divide(Self::PARAM_N, 9), 256);
    const VEC_N_256_SIZE_64: usize = (Self::PARAM_N_MULT / 64) as usize;
    const VEC_N1N2_256_SIZE_64: usize = (ceil_divide(Self::PARAM_N1N2, 256) << 2) as usize;

    const PARAM_DELTA: u32 = 29;
    const PARAM_M: u32 = 8;
    const PARAM_GF_POLY: u32 = 0x11D;
    const PARAM_GF_POLY_WT: u32 = 5;
    const PARAM_GF_POLY_M2: u32 = 4;
    const PARAM_GF_MUL_ORDER: u32 = 255;
    const PARAM_K: u32 = 32;
    const PARAM_G: u32 = 59;
    const PARAM_FFT: u32 = 5;
    const RS_POLY_COEFS: &'static [u32] = &[
        49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71,
        201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4,
        246, 191, 144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
    ];

    const RED_MASK: u64 = 0x1fffffffff;
    const SHA512_BYTES: u32 = 64;
    const SEED_BYTES: u32 = 40;
    const SEEDEXPANDER_MAX_LENGTH: u32 = 4294967295;
    const SALT_SIZE_BYTES: u64 = 16;

    const CODE_ENCODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_256_code_encode;
    const CODE_DECODE: unsafe extern "C" fn(*mut u8, *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_256_code_decode;

    const RM_ENCODE_SINGLE: unsafe extern "C" fn(cdw: *mut u8, msg: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_256_reed_muller_encode_single;
    const RM_DECODE_SINGLE: unsafe extern "C" fn(msg: *mut u8, cdw: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_256_reed_muller_decode_single;

    const ENCAPS_CHOSEN_INPUTS_WITH_SALT: unsafe extern "C" fn(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        m: *const u8,
        u: *const u8,
        r2: *const u8,
        e: *const u8,
        salt: *const u8,
    ) -> oqs_sys::common::OQS_STATUS = oqs_sys::kem::OQS_KEM_hqc_r4_256_encaps_chosen_inputs;

    const PUBLIC_KEY_FROM_STRING: unsafe extern "C" fn(h: *mut u64, s: *mut u64, pk: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_256_public_key_from_string;
    const SECRET_KEY_FROM_STRING: unsafe extern "C" fn(
        x: *mut u64,
        y: *mut u64,
        pk: *mut u8,
        sk: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_r4_256_secret_key_from_string;

    const VECT_MUL: unsafe extern "C" fn(o: *mut u64, a1: *const u8, a1: *const u8) =
        oqs_sys::kem::OQS_KEM_hqc_r4_256_vect_mul;
    const VECT_ADD: unsafe extern "C" fn(O: *mut u64, v1: *const u64, v2: *const u64, u32) =
        oqs_sys::kem::OQS_KEM_hqc_r4_256_vect_add;

    const NUM_SEEDEXPANSIONS: unsafe extern "C" fn(m: *const u8) -> u32 =
        oqs_sys::kem::OQS_KEM_hqc_r4_256_num_seedexpansions;

    const DIVISION_LATENCY: unsafe extern "C" fn(
        m: *const u8,
        pk: *const u8,
        salt: *const u8,
    ) -> u32 = oqs_sys::kem::OQS_KEM_hqc_r4_256_division_latency;
    const CIPHERTEXT_FROM_STRING: unsafe extern "C" fn(
        u: *mut u64,
        v: *mut u64,
        d: *mut u8,
        ct: *const u8,
    ) = oqs_sys::kem::OQS_KEM_hqc_r4_256_ciphertext_from_string;

    const ALGORITHM: oqs::kem::Algorithm = oqs::kem::Algorithm::HqcR4256;

    const INIT_SEED: unsafe extern "C" fn(
        entropy_input: *mut u8,
        personalization_string: *mut u8,
        enlen: u32,
        perlen: u32,
    ) = oqs_sys::kem::OQS_KEM_hqc_r4_256_AVX2_shake_prng_init;
}

#[cfg(test)]
mod test {
    macro_rules! test_with_types {
        ($func:ident, [$($ty:ty),*]) => {
            $(
                $func::<$ty>();
            )*
        }
    }

    macro_rules! test_r3 {
        ($func:ident) => {
            test_with_types!(
                $func,
                [crate::hqc::Hqc128, crate::hqc::Hqc192, crate::hqc::Hqc256]
            );
        };
    }

    macro_rules! test_r34 {
        ($func:ident) => {
            test_with_types!(
                $func,
                [
                    crate::hqc::Hqc128,
                    crate::hqc::Hqc192,
                    crate::hqc::Hqc256,
                    crate::hqc::HqcR4128,
                    crate::hqc::HqcR4192,
                    crate::hqc::HqcR4256
                ]
            );
        };
    }
    pub(crate) use test_r3;
    pub(crate) use test_r34;

    use super::*;

    fn test_code_hqc<T: Hqc>() {
        let mut rng = rand::thread_rng();
        let m = T::sample_message(&mut rng);
        let v = T::code_encode(&m);
        let m2 = T::code_decode(&v);
        assert_eq!(m, m2);
    }

    #[test]
    fn test_code() {
        oqs::init();
        test_r34!(test_code_hqc);
    }

    fn test_rm_hqc<T: Hqc>() {
        let m = T::sample_rm_message();
        let v = T::rm_encode_single(m);
        let m2 = T::rm_decode_single(&v);
        assert_eq!(m, m2);
    }

    #[test]
    fn test_rm() {
        oqs::init();
        test_r34!(test_rm_hqc);
    }

    fn test_encaps_chosen_inputs_hqc<T: Hqc>() {
        let mut rng = rand::thread_rng();
        let m = T::sample_message(&mut rng);
        let kem = T::oqs();
        let (pk, _sk) = kem.keypair().unwrap();
        let r1 = vec![0u8; T::VEC_N_SIZE_BYTES];
        let r2 = vec![0u8; T::VEC_N_SIZE_BYTES];
        let e = vec![0u8; T::VEC_N_SIZE_BYTES];
        let salt = match T::LEAKAGE {
            TimingLeakage::RejectionSampling => None,
            TimingLeakage::DivisionLatency => Some(vec![0u8; T::VEC_K_SIZE_BYTES]),
        };
        let res = T::encaps_chosen_inputs(pk.as_ref(), &m, &r1, &r2, &e, salt.as_deref());
        assert_eq!(res.status, oqs_sys::common::OQS_STATUS::OQS_SUCCESS);
    }

    #[test]
    fn test_encaps_chosen_inputs() {
        oqs::init();
        test_r34!(test_encaps_chosen_inputs_hqc);
    }

    fn test_public_key_from_string_hqc<T: Hqc>() {
        let kem = T::oqs();
        let (pk, _sk) = kem.keypair().unwrap();
        let _res = T::public_key_from_string(pk.as_ref());
    }

    #[test]
    fn test_public_key_from_string() {
        oqs::init();
        test_r34!(test_public_key_from_string_hqc);
    }

    fn test_secret_key_from_string_hqc<T: Hqc>() {
        let kem = T::oqs();
        let (_pk, sk) = kem.keypair().unwrap();
        let _res = T::secret_key_from_string(sk.as_ref());
    }

    #[test]
    fn test_secret_key_from_string() {
        oqs::init();
        test_r34!(test_secret_key_from_string_hqc);
    }

    fn test_vect_add_hqc<T: Hqc>() {
        let a = Poly::zero(T::VEC_N_SIZE_256);
        let b = Poly::zero(T::VEC_N_SIZE_256);
        assert_eq!(a, T::vect_add(&a, &b));
    }

    #[test]
    fn test_vect_add() {
        oqs::init();
        test_r34!(test_vect_add_hqc);
    }

    fn test_vect_mul_hqc<T: Hqc>() {
        let a = Poly::zero(T::VEC_N_SIZE_256);
        let b = Poly::zero(T::VEC_N_SIZE_256);
        assert_eq!(a, T::vect_mul(&a, &b));
    }

    #[test]
    fn test_vect_mul() {
        oqs::init();
        test_r34!(test_vect_mul_hqc);
    }

    fn test_vect_mul_rand_vector_hqc<T: Hqc>() {
        let mut rng = rand::thread_rng();
        let a = Poly::rand(&mut rng, T::VEC_N_SIZE_256);
        let b = Poly::rand(&mut rng, T::VEC_N_SIZE_256);
        assert_eq!(T::vect_mul(&b, &a), T::vect_mul(&a, &b));
    }

    #[test]
    fn test_vect_mul_rand_vector() {
        oqs::init();
        test_r34!(test_vect_mul_rand_vector_hqc);
    }

    fn test_find_high_seedexpansions_msg_hqc<T: Hqc>() {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let m = T::find_high_seedexpansion_message(&mut rng);
            assert_eq!(T::num_seedexpansions(&m), 6);
        }
    }

    #[test]
    fn test_find_high_seedexpansions_msg() {
        oqs::init();
        test_r3!(test_find_high_seedexpansions_msg_hqc);
    }

    fn test_ciphertext_from_string_hqc<T: Hqc>() {
        let mut rng = rand::thread_rng();
        let m = T::sample_message(&mut rng);
        let kem = T::oqs();
        let (pk, _sk) = kem.keypair().unwrap();
        let r1 = vec![0u8; T::VEC_N_SIZE_BYTES];
        let r2 = vec![0u8; T::VEC_N_SIZE_BYTES];
        let e = vec![0u8; T::VEC_N_SIZE_BYTES];
        let salt = match T::LEAKAGE {
            TimingLeakage::RejectionSampling => None,
            TimingLeakage::DivisionLatency => Some(vec![0u8; T::VEC_K_SIZE_BYTES]),
        };
        let res = T::encaps_chosen_inputs(pk.as_ref(), &m, &r1, &r2, &e, salt.as_deref());
        assert_eq!(res.status, oqs_sys::common::OQS_STATUS::OQS_SUCCESS);
        let _res = T::ciphertext_from_string(&res.ct);
    }

    #[test]
    fn test_ciphertext_from_string() {
        oqs::init();
        test_r34!(test_ciphertext_from_string_hqc);
    }
}
