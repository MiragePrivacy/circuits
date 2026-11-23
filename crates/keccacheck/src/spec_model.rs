//! Native model of docs/keccacheck-soundness/01-spec.md, written from that text.
//!
//! It shares no verifier code with the circuit or with upstream's verifier; only
//! the sponge comes from upstream. Each check yields `left - right` as the
//! circuit orders them, so it can be compared with a matrix row residual.

use ark_bn254_05::Fr;
use ark_ff_05::{Field, One, Zero};
use gkr::transcript::Sponge;

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const RHO: [usize; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn half() -> Fr {
    Fr::from(2u64).inverse().unwrap()
}

/// Section 1: eq(a, b) = prod (2 a b + 1 - a - b).
fn eq(a: &[Fr], b: &[Fr]) -> Fr {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .map(|(x, y)| Fr::from(2u64) * x * y + Fr::one() - x - y)
        .product()
}

/// Section 1: xor(a, b) = a + b - 2 a b.
fn xor(a: Fr, b: Fr) -> Fr {
    a + b - Fr::from(2u64) * a * b
}

/// MSB-first bits of `k` as field elements.
fn bits_of(k: usize, width: usize) -> Vec<Fr> {
    (0..width)
        .map(|m| Fr::from(((k >> (width - 1 - m)) & 1) as u64))
        .collect()
}

/// Section 1: T~(z) = sum_k eq(z, k) T(k).
fn mle(table: &[Fr], z: &[Fr]) -> Fr {
    assert_eq!(table.len(), 1 << z.len());
    table
        .iter()
        .enumerate()
        .map(|(k, value)| eq(z, &bits_of(k, z.len())) * value)
        .sum()
}

/// Section 5: rot_s(a, c).
fn rot(s: usize, a: &[Fr], c: &[Fr]) -> Fr {
    let split = a.len() - 6;
    let suffix: Fr = (0..64)
        .map(|u| eq(&a[split..], &bits_of((u + s) % 64, 6)) * eq(&c[split..], &bits_of(u, 6)))
        .sum();
    eq(&a[..split], &c[..split]) * suffix
}

struct Transcript<'a> {
    sponge: Sponge,
    proof: &'a [Fr],
    at: usize,
}

impl Transcript<'_> {
    fn read(&mut self) -> Fr {
        let value = self.proof[self.at];
        self.at += 1;
        self.sponge.absorb(value);
        value
    }

    fn read_many(&mut self, count: usize) -> Vec<Fr> {
        (0..count).map(|_| self.read()).collect()
    }

    fn squeeze(&mut self, count: usize) -> Vec<Fr> {
        (0..count).map(|_| self.sponge.squeeze()).collect()
    }

    /// Section 1: SC(d, m, c).
    fn sumcheck(&mut self, degree: usize, vars: usize, mut c: Fr) -> (Fr, Vec<Fr>) {
        let mut point = Vec::with_capacity(vars);
        for _ in 0..vars {
            let p = self.read_many(degree);
            let p0 = (c - p.iter().sum::<Fr>()) * half();
            let r = self.sponge.squeeze();
            point.push(r);
            let mut power = r;
            c = p0;
            for coefficient in &p {
                c += *coefficient * power;
                power *= r;
            }
        }
        (c, point)
    }
}

/// Section 3: the statement sponge, over lane-major words.
pub fn derive_r(input: &[u64], output: &[u64], log_h: usize) -> Vec<Fr> {
    let mut sponge = Sponge::new();
    let tag = u128::from_le_bytes(*b"mirage/kcck/stmt");
    sponge.absorb(Fr::from(tag));
    sponge.absorb(Fr::from(1u64 << log_h));
    let two_64 = Fr::from(2u64).pow([64u64]);
    for words in [input, output] {
        for chunk in words.chunks(3) {
            let mut packed = Fr::zero();
            let mut scale = Fr::one();
            for word in chunk {
                packed += Fr::from(*word) * scale;
                scale *= two_64;
            }
            sponge.absorb(packed);
        }
    }
    (0..log_h).map(|_| sponge.squeeze()).collect()
}

fn add_col(i: usize, a: usize) -> usize {
    (i % 5 + a) % 5 + i - i % 5
}

/// Section 6.3: rho_i = pi_{P(i)}, walking P(1) = PI[0], P(PI[m]) = PI[m+1].
fn rho_from_pi(pi: &[Fr]) -> Vec<Fr> {
    let mut rho = vec![pi[0]; 25];
    let mut last = 1;
    for target in PI {
        rho[last] = pi[target];
        last = target;
    }
    rho
}

fn dot(a: &[Fr], b: &[Fr]) -> Fr {
    a.iter().zip(b).map(|(x, y)| *x * y).sum()
}

/// Every check as `(label, left - right)`, in verification order.
pub fn residuals(input: &[u64], output: &[u64], proof: &[Fr]) -> Vec<(String, Fr)> {
    let h = input.len() / 25;
    let log_h = h.ilog2() as usize;
    let n = log_h + 6;
    let mut out = Vec::new();
    let r = derive_r(input, output, log_h);

    // Section 4.
    let mut t = Transcript {
        sponge: Sponge::new(),
        proof,
        at: 0,
    };
    r.iter().for_each(|value| t.sponge.absorb(*value));
    let mut beta = t.squeeze(25);
    let sum = t.read();
    let expected: Fr = (0..25)
        .map(|i| {
            let words: Vec<Fr> = (0..h).map(|j| Fr::from(output[i * h + j])).collect();
            beta[i] * mle(&words, &r)
        })
        .sum();
    out.push(("output sum".to_owned(), sum - expected));
    let (c1, r_x) = t.sumcheck(2, log_h, sum);
    let words_r_x = t.read();
    out.push((
        "output word reduction".to_owned(),
        c1 - words_r_x * eq(&r, &r_x),
    ));
    let (c2, r_y) = t.sumcheck(2, 6, words_r_x);
    let bit_eval = t.read();
    let pow: Vec<Fr> = (0..64).map(|b| Fr::from(1u64 << b)).collect();
    out.push((
        "output bit reduction".to_owned(),
        c2 - mle(&pow, &r_y) * bit_eval,
    ));
    let mut sum = bit_eval;
    let mut alpha = [r_x, r_y].concat();

    let mut a = Vec::new();
    for round in (0..24).rev() {
        let name = |check: &str| format!("round {round}: {check}");

        // 6.1
        let (ve, v1) = t.sumcheck(3, n, sum);
        let chi_00 = t.read();
        let chi_rlc = t.read();
        let rc_table: Vec<Fr> = (0..64).map(|b| Fr::from((RC[round] >> b) & 1)).collect();
        let rc = mle(&rc_table, &v1[n - 6..]);
        out.push((
            name("iota"),
            eq(&alpha, &v1) * (beta[0] * xor(chi_00, rc) + chi_rlc) - ve,
        ));

        // 6.2
        let x = t.sponge.squeeze();
        let y = t.sponge.squeeze();
        beta[0] *= x;
        beta[1..].iter_mut().for_each(|b| *b *= y);
        let (ve, v2) = t.sumcheck(4, n, beta[0] * chi_00 + y * chi_rlc);
        let pi = t.read_many(25);
        let chi: Fr = (0..25)
            .map(|i| {
                let inner = (Fr::one() - pi[add_col(i, 1)]) * pi[add_col(i, 2)];
                beta[i] * xor(pi[i], inner)
            })
            .sum();
        out.push((name("chi"), eq(&v1, &v2) * chi - ve));

        // 6.3, 6.4
        let rho = rho_from_pi(&pi);
        beta = t.squeeze(25);
        let (ve, v3) = t.sumcheck(2, n, dot(&beta, &rho));
        let theta = t.read_many(25);
        let checksum: Fr = (0..25)
            .map(|i| beta[i] * rot(RHO[i], &v2, &v3) * theta[i])
            .sum();
        out.push((name("rho"), checksum - ve));

        // 6.5
        let theta_hat: Vec<Fr> = theta
            .iter()
            .map(|value| Fr::one() - *value - *value)
            .collect();
        beta = t.squeeze(25);
        let (ve, v4) = t.sumcheck(3, n, dot(&beta, &theta_hat));
        let ai = t.read_many(5);
        let d = t.read_many(5);
        out.push((name("theta"), eq(&v3, &v4) * dot(&d, &ai) - ve));

        // 6.6
        let bd = t.squeeze(5);
        let (ve, v5) = t.sumcheck(3, n, dot(&bd, &d));
        let c = t.read_many(5);
        let rc1 = t.read_many(5);
        let checksum: Fr = (0..5)
            .map(|x| bd[x] * eq(&v4, &v5) * c[(x + 4) % 5] * rc1[(x + 1) % 5])
            .sum();
        out.push((name("theta_d"), checksum - ve));

        // 6.7
        let bc = t.squeeze(5);
        let brc = t.squeeze(5);
        let (ve, v6) = t.sumcheck(6, n, dot(&bc, &c) + dot(&brc, &rc1));
        let opened = t.read_many(25);
        let checksum: Fr = (0..5)
            .map(|x| {
                let product: Fr = (0..5).map(|y| opened[x + 5 * y]).product();
                (bc[x] * eq(&v5, &v6) + brc[x] * rot(1, &v5, &v6)) * product
            })
            .sum();
        out.push((name("theta_c"), checksum - ve));

        // 6.8
        let b = t.squeeze(5);
        for x in 0..5 {
            for y in 0..5 {
                beta[x + 5 * y] *= b[x];
            }
        }
        let ba = t.squeeze(25);
        let (ve, v7) = t.sumcheck(2, n, dot(&b, &ai) + dot(&ba, &opened));
        let ah = t.read_many(25);
        let checksum: Fr = (0..25)
            .map(|i| (beta[i] * eq(&v4, &v7) + ba[i] * eq(&v6, &v7)) * ah[i])
            .sum();
        out.push((name("theta_a"), checksum - ve));
        a = ah
            .iter()
            .map(|value| (Fr::one() - value) * half())
            .collect();
        alpha = v7;

        // 6.9
        if round != 0 {
            beta = t.squeeze(25);
            sum = dot(&beta, &a);
        }
    }

    // 6.10
    for i in 0..25 {
        let table: Vec<Fr> = (0..h)
            .flat_map(|j| {
                let word = input[i * h + j];
                (0..64).map(move |b| Fr::from((word >> b) & 1))
            })
            .collect();
        out.push((format!("input lane {i}"), mle(&table, &alpha) - a[i]));
    }
    assert_eq!(t.at, proof.len(), "section 7: proof not exhausted");
    out
}
