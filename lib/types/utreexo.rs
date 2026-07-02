//! Utreexo accumulator support.
//!
//! Full nodes keep the complete accumulator locally. Transactions do not carry
//! Utreexo proofs; proofs are only a serving format for lite clients.

use std::{collections::HashMap, io::Cursor};

use borsh::{BorshDeserialize, BorshSerialize};
use rustreexo::accumulator::{
    mem_forest::MemForest, node_hash::BitcoinNodeHash, proof::Proof,
    stump::Stump,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{
    FilledOutput, Hash, OutPoint, PointedOutput, hashes,
    serde_hexstr_human_readable,
};

#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Copy,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct UtreexoHash(#[serde(with = "serde_hexstr_human_readable")] pub Hash);

impl std::fmt::Debug for UtreexoHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Display for UtreexoHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl utoipa::PartialSchema for UtreexoHash {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        let obj =
            utoipa::openapi::Object::with_type(utoipa::openapi::Type::String);
        utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(obj))
    }
}

impl ToSchema for UtreexoHash {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UtreexoHash")
    }
}

impl From<Hash> for UtreexoHash {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<UtreexoHash> for Hash {
    fn from(hash: UtreexoHash) -> Self {
        hash.0
    }
}

impl From<UtreexoHash> for BitcoinNodeHash {
    fn from(hash: UtreexoHash) -> Self {
        Self::new(hash.0)
    }
}

impl TryFrom<BitcoinNodeHash> for UtreexoHash {
    type Error = String;

    fn try_from(hash: BitcoinNodeHash) -> Result<Self, Self::Error> {
        match hash {
            BitcoinNodeHash::Some(hash) => Ok(Self(hash)),
            BitcoinNodeHash::Empty => {
                Err("unexpected empty utreexo hash".to_owned())
            }
            BitcoinNodeHash::Placeholder => {
                Err("unexpected placeholder utreexo hash".to_owned())
            }
        }
    }
}

#[derive(
    Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ToSchema,
)]
pub struct UtreexoProof {
    pub targets: Vec<u64>,
    pub hashes: Vec<UtreexoHash>,
}

impl From<Proof<BitcoinNodeHash>> for UtreexoProof {
    fn from(proof: Proof<BitcoinNodeHash>) -> Self {
        let hashes = proof
            .hashes
            .into_iter()
            .map(|hash| {
                UtreexoHash::try_from(hash)
                    .expect("proof hashes should be concrete hashes")
            })
            .collect();
        Self {
            targets: proof.targets,
            hashes,
        }
    }
}

#[derive(Default)]
pub struct Accumulator(pub MemForest<BitcoinNodeHash>);

impl std::fmt::Debug for Accumulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Accumulator")
            .field("leaves", &self.0.leaves)
            .field("roots", &self.roots())
            .finish()
    }
}

impl Serialize for Accumulator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.0
            .serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            Serialize::serialize(&bytes, serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Accumulator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let hex = <String as Deserialize<'de>>::deserialize(deserializer)?;
            hex::decode(hex).map_err(serde::de::Error::custom)?
        } else {
            <Vec<u8> as Deserialize<'de>>::deserialize(deserializer)?
        };
        MemForest::<BitcoinNodeHash>::deserialize(Cursor::new(bytes))
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl Accumulator {
    fn root_to_commitment_hash(root: BitcoinNodeHash) -> Option<UtreexoHash> {
        match root {
            BitcoinNodeHash::Some(hash) => Some(UtreexoHash(hash)),
            BitcoinNodeHash::Empty => None,
            BitcoinNodeHash::Placeholder => {
                panic!("accumulator roots should not be placeholders")
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        MemForest::<BitcoinNodeHash>::deserialize(Cursor::new(bytes))
            .map(Self)
            .map_err(|err| err.to_string())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        self.0
            .serialize(&mut bytes)
            .map_err(|err| err.to_string())?;
        Ok(bytes)
    }

    pub fn roots(&self) -> Vec<UtreexoHash> {
        self.0
            .get_roots()
            .iter()
            .filter_map(|root| Self::root_to_commitment_hash(root.get_data()))
            .collect()
    }

    fn root_hashes(&self) -> Vec<BitcoinNodeHash> {
        self.0
            .get_roots()
            .iter()
            .map(|root| root.get_data())
            .collect()
    }

    pub fn stump(&self) -> AccumulatorStump {
        AccumulatorStump(Stump {
            leaves: self.0.leaves,
            roots: self.root_hashes(),
        })
    }

    pub(crate) fn prove_raw(
        &self,
        targets: &[UtreexoHash],
    ) -> Result<Proof<BitcoinNodeHash>, String> {
        let targets: Vec<BitcoinNodeHash> =
            targets.iter().copied().map(Into::into).collect();
        self.0.prove(&targets)
    }

    pub fn prove(
        &self,
        targets: &[UtreexoHash],
    ) -> Result<UtreexoProof, String> {
        self.prove_raw(targets).map(Into::into)
    }

    pub fn roots_after_diff(
        &self,
        diff: &AccumulatorDiff,
    ) -> Result<Vec<UtreexoHash>, String> {
        let proof = if diff.deletions.is_empty() {
            Proof::default()
        } else {
            self.prove_raw(&diff.deletions)?
        };
        self.stump().roots_after_diff(diff, &proof)
    }

    pub fn apply_diff(&mut self, diff: &AccumulatorDiff) -> Result<(), String> {
        let additions: Vec<BitcoinNodeHash> =
            diff.additions.iter().copied().map(Into::into).collect();
        let deletions: Vec<BitcoinNodeHash> =
            diff.deletions.iter().copied().map(Into::into).collect();
        self.0.modify(&additions, &deletions)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccumulatorDiff {
    pub additions: Vec<UtreexoHash>,
    pub deletions: Vec<UtreexoHash>,
}

impl AccumulatorDiff {
    pub fn insert(&mut self, leaf: UtreexoHash) {
        self.additions.push(leaf);
    }

    pub fn remove(&mut self, leaf: UtreexoHash) {
        self.deletions.push(leaf);
    }

    pub fn is_empty(&self) -> bool {
        self.additions.is_empty() && self.deletions.is_empty()
    }

    pub fn clear(&mut self) {
        self.additions.clear();
        self.deletions.clear();
    }

    pub fn normalize(&mut self) {
        let mut additions = HashMap::<UtreexoHash, usize>::new();
        for leaf in &self.additions {
            *additions.entry(*leaf).or_default() += 1;
        }

        let mut cancel = HashMap::<UtreexoHash, usize>::new();
        for leaf in &self.deletions {
            let Some(addition_count) = additions.get_mut(leaf) else {
                continue;
            };
            if *addition_count == 0 {
                continue;
            }
            *addition_count -= 1;
            *cancel.entry(*leaf).or_default() += 1;
        }

        let mut cancel_additions = cancel.clone();
        self.additions.retain(|leaf| {
            let Some(cancel_count) = cancel_additions.get_mut(leaf) else {
                return true;
            };
            if *cancel_count == 0 {
                return true;
            }
            *cancel_count -= 1;
            false
        });

        self.deletions.retain(|leaf| {
            let Some(cancel_count) = cancel.get_mut(leaf) else {
                return true;
            };
            if *cancel_count == 0 {
                return true;
            }
            *cancel_count -= 1;
            false
        });
    }

    pub fn into_inverse(self) -> Self {
        Self {
            additions: self.deletions,
            deletions: self.additions,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AccumulatorStump(Stump<BitcoinNodeHash>);

impl AccumulatorStump {
    pub fn roots(&self) -> Vec<UtreexoHash> {
        self.0
            .roots
            .iter()
            .copied()
            .filter_map(Accumulator::root_to_commitment_hash)
            .collect()
    }

    pub(crate) fn next(
        &self,
        diff: &AccumulatorDiff,
        proof: &Proof<BitcoinNodeHash>,
    ) -> Result<Self, String> {
        let additions: Vec<BitcoinNodeHash> =
            diff.additions.iter().copied().map(Into::into).collect();
        let deletions: Vec<BitcoinNodeHash> =
            diff.deletions.iter().copied().map(Into::into).collect();
        let (stump, _) = self.0.modify(&additions, &deletions, proof)?;
        Ok(Self(stump))
    }

    pub(crate) fn roots_after_diff(
        &self,
        diff: &AccumulatorDiff,
        proof: &Proof<BitcoinNodeHash>,
    ) -> Result<Vec<UtreexoHash>, String> {
        self.next(diff, proof).map(|stump| stump.roots())
    }
}

pub fn leaf_hash(outpoint: &OutPoint, output: &FilledOutput) -> UtreexoHash {
    let pointed_output = PointedOutput {
        outpoint: *outpoint,
        output: output.clone(),
    };
    UtreexoHash(hashes::hash_with_scratch_buffer(&pointed_output))
}

#[cfg(test)]
mod test {
    use super::*;

    fn hash(byte: u8) -> UtreexoHash {
        UtreexoHash([byte; blake3::OUT_LEN])
    }

    #[test]
    fn roots_after_diff_previews_without_mutating() {
        let mut live = Accumulator::default();
        let mut expected = Accumulator::default();
        let mut initial = AccumulatorDiff::default();
        for byte in 1..=8 {
            initial.insert(hash(byte));
        }
        live.apply_diff(&initial).unwrap();
        expected.apply_diff(&initial).unwrap();

        let roots_before = live.roots();
        let mut diff = AccumulatorDiff::default();
        diff.remove(hash(2));
        diff.remove(hash(5));
        diff.insert(hash(9));
        diff.insert(hash(10));

        let preview_roots = live.roots_after_diff(&diff).unwrap();
        expected.apply_diff(&diff).unwrap();

        assert_eq!(live.roots(), roots_before);
        assert_eq!(preview_roots, expected.roots());
    }

    #[test]
    fn accumulator_diff_normalize_cancels_matching_leaves() {
        let mut diff = AccumulatorDiff {
            additions: vec![hash(1), hash(2), hash(1)],
            deletions: vec![hash(1), hash(3), hash(1)],
        };

        diff.normalize();

        assert_eq!(diff.additions, vec![hash(2)]);
        assert_eq!(diff.deletions, vec![hash(3)]);
    }
}
