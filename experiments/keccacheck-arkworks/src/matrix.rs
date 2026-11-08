//! Direct evaluation of compiled R1CS matrices.
//!
//! `ConstraintSystem::is_satisfied` reads cached linear-combination values when
//! they exist, so it can miss an edit to the witness. Everything here reads only
//! the matrices and the instance and witness assignments.

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use ark_relations::gr1cs::{ConstraintSystemRef, R1CS_PREDICATE_LABEL, SynthesisError, Variable};

pub type Row = Vec<(Fr, usize)>;

/// Finalized matrices with the assignment they are evaluated against.
pub struct Compiled {
    pub a: Vec<Row>,
    pub b: Vec<Row>,
    pub c: Vec<Row>,
    /// `[1, instance.., witness..]`; empty after setup-mode synthesis.
    pub z: Vec<Fr>,
    pub num_instance: usize,
}

impl Compiled {
    /// Finalizes `cs`, inlining every linear combination.
    pub fn from_cs(cs: &ConstraintSystemRef<Fr>) -> Result<Self, SynthesisError> {
        cs.finalize();
        let mut matrices = cs
            .to_matrices()?
            .remove(R1CS_PREDICATE_LABEL)
            .ok_or(SynthesisError::MissingCS)?;
        let c = matrices.pop().ok_or(SynthesisError::MissingCS)?;
        let b = matrices.pop().ok_or(SynthesisError::MissingCS)?;
        let a = matrices.pop().ok_or(SynthesisError::MissingCS)?;
        let inner = cs.borrow().ok_or(SynthesisError::MissingCS)?;
        let z = inner
            .assignments
            .instance_assignment
            .iter()
            .chain(&inner.assignments.witness_assignment)
            .copied()
            .collect();
        Ok(Self {
            a,
            b,
            c,
            z,
            num_instance: cs.num_instance_variables(),
        })
    }

    pub fn num_rows(&self) -> usize {
        self.a.len()
    }

    /// Column of a witness or instance variable; `None` for other kinds.
    pub fn column(&self, variable: Variable) -> Option<usize> {
        if variable.is_lc() || variable.is_zero() {
            return None;
        }
        variable.get_variable_index(self.num_instance)
    }

    fn dot(row: &Row, z: &[Fr]) -> Fr {
        row.iter().map(|(coeff, col)| *coeff * z[*col]).sum()
    }

    /// `A.z * B.z - C.z` for one row.
    pub fn residual_at(&self, row: usize, z: &[Fr]) -> Fr {
        Self::dot(&self.a[row], z) * Self::dot(&self.b[row], z) - Self::dot(&self.c[row], z)
    }

    /// Indices of unsatisfied rows under the stored assignment.
    pub fn unsatisfied(&self) -> Vec<usize> {
        self.unsatisfied_under(&self.z)
    }

    /// Indices of unsatisfied rows under an arbitrary assignment.
    pub fn unsatisfied_under(&self, z: &[Fr]) -> Vec<usize> {
        (0..self.num_rows())
            .filter(|row| !self.residual_at(*row, z).is_zero())
            .collect()
    }

    /// For each column, the rows that mention it.
    pub fn rows_by_column(&self) -> Vec<Vec<u32>> {
        let mut columns = vec![Vec::new(); self.z.len().max(self.max_column() + 1)];
        for matrix in [&self.a, &self.b, &self.c] {
            for (row, entries) in matrix.iter().enumerate() {
                for (_, col) in entries {
                    if columns[*col].last() != Some(&(row as u32)) {
                        columns[*col].push(row as u32);
                    }
                }
            }
        }
        for rows in &mut columns {
            rows.sort_unstable();
            rows.dedup();
        }
        columns
    }

    fn max_column(&self) -> usize {
        [&self.a, &self.b, &self.c]
            .iter()
            .flat_map(|m| m.iter().flatten().map(|(_, col)| *col))
            .max()
            .unwrap_or(0)
    }

    /// Columns not fixed by forward substitution from `free`.
    ///
    /// A row fixes a column when A and B involve only known columns and C has
    /// exactly one unknown column, which then equals a function of known values
    /// because its coefficient is non-zero. If the result is empty, every
    /// satisfying assignment is a function of `free` and the instance.
    pub fn undetermined(&self, free: &[usize]) -> Vec<usize> {
        self.forward_substitute(free)
            .0
            .iter()
            .enumerate()
            .filter_map(|(col, known)| (!known).then_some(col))
            .collect()
    }

    /// Rows that only define a column in the forward substitution from `free`.
    ///
    /// Any other row restricts the values of known columns, so together with
    /// `undetermined` this lists everything the relation actually checks.
    pub fn defining_rows(&self, free: &[usize]) -> Vec<bool> {
        self.forward_substitute(free).1
    }

    fn forward_substitute(&self, free: &[usize]) -> (Vec<bool>, Vec<bool>) {
        let total = self.max_column() + 1;
        let mut known = vec![false; total.max(self.num_instance)];
        known[..self.num_instance].fill(true);
        for col in free {
            known[*col] = true;
        }
        let mut defining = vec![false; self.num_rows()];
        for row in 0..self.num_rows() {
            let all_known = |entries: &Row| entries.iter().all(|(_, col)| known[*col]);
            if !all_known(&self.a[row]) || !all_known(&self.b[row]) {
                continue;
            }
            let mut unknown = self.c[row].iter().filter(|(_, col)| !known[*col]);
            if let (Some((coeff, col)), None) = (unknown.next(), unknown.next())
                && !coeff.is_zero()
            {
                let col = *col;
                known[col] = true;
                defining[row] = true;
            }
        }
        (known, defining)
    }

    /// Columns provably in {0, 1} in every satisfying assignment.
    ///
    /// A column enters the set through `x * (1 - x) = 0`, or when C is the only
    /// place it appears in a row whose other columns are all in the set and it
    /// takes a value in {0, 1} for every Boolean choice of those columns.
    pub fn boolean_columns(&self) -> Vec<bool> {
        const MAX_SUPPORT: usize = 8;
        let mut boolean = vec![false; self.max_column() + 1];
        boolean[0] = true;
        for row in 0..self.num_rows() {
            let (a, b, c) = (&self.a[row], &self.b[row], &self.c[row]);
            if c.is_empty()
                && let Some(col) = booleanity_target(a, b)
            {
                boolean[col] = true;
                continue;
            }
            let mut unknown = c.iter().filter(|(_, col)| !boolean[*col]);
            let (Some((coeff, target)), None) = (unknown.next(), unknown.next()) else {
                continue;
            };
            let (coeff, target) = (*coeff, *target);
            let mut support: Vec<usize> = a
                .iter()
                .chain(b)
                .chain(c)
                .map(|(_, col)| *col)
                .filter(|col| *col != target && *col != 0)
                .collect();
            support.sort_unstable();
            support.dedup();
            if support.len() > MAX_SUPPORT
                || coeff.is_zero()
                || !support.iter().all(|col| boolean[*col])
                || a.iter().chain(b).any(|(_, col)| *col == target)
            {
                continue;
            }
            let value_at = |choice: usize, row_entries: &Row| -> Fr {
                row_entries
                    .iter()
                    .filter(|(_, col)| *col != target)
                    .map(|(entry, col)| {
                        let value = if *col == 0 {
                            Fr::one()
                        } else {
                            let bit = support.iter().position(|s| s == col).unwrap();
                            Fr::from(((choice >> bit) & 1) as u64)
                        };
                        *entry * value
                    })
                    .sum()
            };
            let inverse = ark_ff::Field::inverse(&coeff).unwrap();
            boolean[target] = (0..1usize << support.len()).all(|choice| {
                let solved =
                    (value_at(choice, a) * value_at(choice, b) - value_at(choice, c)) * inverse;
                solved.is_zero() || solved.is_one()
            });
        }
        boolean
    }
}

/// `x` when `{a, b}` is `{x, 1 - x}` up to a common scale.
fn booleanity_target(a: &Row, b: &Row) -> Option<usize> {
    let single = |row: &Row| match row.as_slice() {
        [(coeff, col)] if *col != 0 && !coeff.is_zero() => Some(*col),
        _ => None,
    };
    let complement = |row: &Row, x: usize| {
        let [(k1, c1), (k2, c2)] = row.as_slice() else {
            return false;
        };
        (*c1 == 0 && *c2 == x && *k1 + *k2 == Fr::zero())
            || (*c2 == 0 && *c1 == x && *k1 + *k2 == Fr::zero())
    };
    match (single(a), single(b)) {
        (Some(x), _) if complement(b, x) => Some(x),
        (_, Some(x)) if complement(a, x) => Some(x),
        _ => None,
    }
}
