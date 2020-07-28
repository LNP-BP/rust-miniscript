// Miniscript
// Written in 2020 by
//     Dr Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use super::decode::Terminal;
use super::Error;
use super::{Miniscript, MiniscriptKey, ScriptContext};
use std::collections::VecDeque;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

/// Iterator-related extensions for [Miniscript]
impl<PK: MiniscriptKey, Ctx: ScriptContext> Miniscript<PK, Ctx> {
    /// Creates a new [Iter] iterator that will iterate over all [Miniscript] items within
    /// AST by traversing its branches. For the specific algorithm please see
    /// [Iter::next] function.
    pub fn iter(&self) -> Iter<PK, Ctx> {
        Iter::new(self)
    }

    /// Creates a new [PubkeyIter] iterator that will iterate over all plain public keys (and not
    /// key hash values) present in [Miniscript] items within AST by traversing all its branches.
    /// For the specific algorithm please see [PubkeyIter::next] function.
    pub fn iter_pubkeys(&self) -> PubkeyIter<PK, Ctx> {
        PubkeyIter::new(self)
    }

    /// Creates a new [PubkeyHashIter] iterator that will iterate over all plain public keys (and not
    /// key hash values) present in Miniscript items within AST by traversing all its branches.
    /// For the specific algorithm please see [PubkeyHashIter::next] function.
    pub fn iter_pubkey_hashes(&self) -> PubkeyHashIter<PK, Ctx> {
        PubkeyHashIter::new(self)
    }

    /// Creates a new [PubkeyAndHashIter] iterator that will iterate over all plain public keys and
    /// key hash values present in Miniscript items within AST by traversing all its branches.
    /// For the specific algorithm please see [PubeyAndHashIter::next] function.
    pub fn iter_pubkeys_and_hashes(&self) -> PubkeyAndHashIter<PK, Ctx> {
        PubkeyAndHashIter::new(self)
    }

    /// Enumerates all child nodes of the current AST node (`self`) and returns a `Vec` referencing
    /// them.
    pub fn branches(&self) -> Vec<&Miniscript<PK, Ctx>> {
        use Terminal::*;
        match &self.node {
            PkK(_) | PkH(_) | Multi(_, _) => vec![],

            Alt(node) | Swap(node) | Check(node) | DupIf(node) | Verify(node) | NonZero(node)
            | ZeroNotEqual(node) => vec![node],

            AndV(node1, node2)
            | AndB(node1, node2)
            | OrB(node1, node2)
            | OrD(node1, node2)
            | OrC(node1, node2)
            | OrI(node1, node2) => vec![node1, node2],

            AndOr(node1, node2, node3) => vec![node1, node2, node3],

            Thresh(_, node_vec) => node_vec.iter().map(Arc::deref).collect(),

            _ => vec![],
        }
    }

    /// Returns `Vec` with cloned version of all public keys from the current miniscript item,
    /// if any. Otherwise returns an empty `Vec`.
    ///
    /// NB: The function analyzes only single miniscript item and not any of its descendants in AST.
    /// To obtain a list of all public keys within AST use [`iter_pubkeys()`] function, for example
    /// `miniscript.iter_pubkeys().collect()`.
    pub fn get_pubkeys(&self) -> Vec<PK> {
        match self.node.clone() {
            Terminal::PkK(key) => vec![key],
            Terminal::Multi(_, keys) => keys,
            _ => vec![],
        }
    }

    /// Returns `Vec` with hashes of all public keys from the current miniscript item, if any.
    /// Otherwise returns an empty `Vec`.
    ///
    /// For each public key the function computes hash; for each hash of the public key the function
    /// returns it's cloned copy.
    ///
    /// NB: The function analyzes only single miniscript item and not any of its descendants in AST.
    /// To obtain a list of all public key hashes within AST use [`iter_pubkey_hashes()`] function,
    /// for example `miniscript.iter_pubkey_hashes().collect()`.
    pub fn get_pubkey_hashes(&self) -> Vec<PK::Hash> {
        match self.node.clone() {
            Terminal::PkH(hash) => vec![hash],
            Terminal::PkK(key) => vec![key.to_pubkeyhash()],
            Terminal::Multi(_, keys) => keys.iter().map(PK::to_pubkeyhash).collect(),
            _ => vec![],
        }
    }

    /// Returns `Vec` of [PubkeyOrHash] entries, representing either public keys or public key
    /// hashes, depending on the data from the current miniscript item. If there is no public
    /// keys or hashes, the function returns an empty `Vec`.
    ///
    /// NB: The function analyzes only single miniscript item and not any of its descendants in AST.
    /// To obtain a list of all public keys or hashes within AST use [`iter_pubkeys_and_hashes()`]
    /// function, for example `miniscript.iter_pubkeys_and_hashes().collect()`.
    pub fn get_pubkeys_and_hashes(&self) -> Vec<PubkeyOrHash<PK>> {
        use self::PubkeyOrHash::*;
        match self.node.clone() {
            Terminal::PkH(hash) => vec![HashedPubkey(hash)],
            Terminal::PkK(key) => vec![PlainPubkey(key)],
            Terminal::Multi(_, keys) => keys.into_iter().map(PlainPubkey).collect(),
            _ => vec![],
        }
    }

    /// Iterates over all public keys and public key hashes by traversing a complete Miniscript
    /// AST; calls `processor` callback providing each of the found public key or hash and
    /// replaces miniscript item with the new one constructed out of results returned from the
    /// callback. The function returns a new Miniscript AST.
    ///
    /// If you need to fail the process due to error, return `None` value from the processor
    /// and replacement will fail with [Error::PubkeyProcessorFailure] error.
    pub fn replace_pubkeys_and_hashes(
        &self,
        processor: &impl Fn(PubkeyOrHash<PK>) -> Option<PubkeyOrHash<PK>>,
    ) -> Result<Self, Error> {
        use self::PubkeyOrHash::*;
        use Terminal::*;

        macro_rules! process {
            [ $value:ident ] => (
                Arc::new($value.replace_pubkeys_and_hashes(processor)?)
            )
        }

        let node = match &self.node {
            PkK(key) => {
                match processor(PlainPubkey(key.clone())).ok_or(Error::PubkeyProcessorFailure)? {
                    PlainPubkey(key) => PkK(key),
                    HashedPubkey(keyhash) => PkH(keyhash),
                }
            }
            PkH(keyhash) => match processor(HashedPubkey(keyhash.clone()))
                .ok_or(Error::PubkeyProcessorFailure)?
            {
                PlainPubkey(key) => PkK(key),
                HashedPubkey(keyhash) => PkH(keyhash),
            },
            Multi(count, keys) => Multi(
                *count,
                keys.into_iter()
                    .try_fold(Vec::<PK>::new(), |mut vec, key| {
                        match processor(PlainPubkey(key.clone()))
                            .ok_or(Error::PubkeyProcessorFailure)?
                        {
                            PlainPubkey(key) => {
                                vec.push(key);
                                Ok(vec)
                            }
                            HashedPubkey(_) => Err(Error::UnexpectedPubkeyHash),
                        }
                    })?,
            ),

            Alt(node) => Alt(process![node]),
            Swap(node) => Swap(process![node]),
            Check(node) => Check(process![node]),
            DupIf(node) => DupIf(process![node]),
            Verify(node) => Verify(process![node]),
            NonZero(node) => NonZero(process![node]),
            ZeroNotEqual(node) => ZeroNotEqual(process![node]),

            AndV(node1, node2) => AndV(process![node1], process![node2]),
            AndB(node1, node2) => AndB(process![node1], process![node2]),
            OrB(node1, node2) => OrB(process![node1], process![node2]),
            OrD(node1, node2) => OrD(process![node1], process![node2]),
            OrC(node1, node2) => OrC(process![node1], process![node2]),
            OrI(node1, node2) => OrI(process![node1], process![node2]),

            AndOr(node1, node2, node3) => AndOr(process![node1], process![node2], process![node3]),

            Thresh(count, node_vec) => Thresh(
                *count,
                node_vec
                    .into_iter()
                    .try_fold::<_, _, Result<Vec<Arc<Miniscript<PK, Ctx>>>, Error>>(
                        Vec::<Arc<Miniscript<PK, Ctx>>>::new(),
                        |mut vec, ms| {
                            vec.push(process![ms]);
                            Ok(vec)
                        },
                    )?,
            ),

            _ => self.node.clone(),
        };
        Ok(Miniscript { node, ..*self })
    }
}

/// Iterator for traversing all [Miniscript] miniscript AST references starting from some specific
/// node which constructs the iterator via [Miniscript::iter] method.
pub struct Iter<'a, Pk: 'a + MiniscriptKey, Ctx: ScriptContext> {
    next: Option<&'a Miniscript<Pk, Ctx>>,
    path: Vec<(&'a Miniscript<Pk, Ctx>, usize)>,
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> Iter<'a, Pk, Ctx> {
    fn new(miniscript: &'a Miniscript<Pk, Ctx>) -> Self {
        Iter {
            next: Some(miniscript),
            path: vec![],
        }
    }
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> Iterator for Iter<'a, Pk, Ctx> {
    type Item = &'a Miniscript<Pk, Ctx>;

    /// First, the function returns `self`, then the first child of the self (if any),
    /// then proceeds to the child of the child — down to a leaf of the tree in its first branch.
    /// When the leaf is reached, it goes in the reverse direction on the same branch until it
    /// founds a first branching node that had more than a single branch and returns it, traversing
    /// it with the same algorithm again.
    ///
    /// For example, for the given AST
    /// ```text
    /// A --+--> B -----> C --+--> D -----> E
    ///     |                 |
    ///     |                 +--> F
    ///     |                 |
    ///     |                 +--> G --+--> H
    ///     |                          |
    ///     |                          +--> I -----> J
    ///     +--> K
    /// ```
    /// `Iter::next()` will iterate over the nodes in the following order:
    /// `A > B > C > D > E > F > G > I > J > K`
    ///
    /// To enumerate the branches iterator uses [Miniscript::branches] function.
    fn next(&mut self) -> Option<Self::Item> {
        let mut curr = self.next;
        if let None = curr {
            while let Some((node, child)) = self.path.pop() {
                curr = node.branches().get(child).map(|x| *x);
                if curr.is_some() {
                    self.path.push((node, child + 1));
                    break;
                }
            }
        }
        if let Some(node) = curr {
            self.next = node.branches().first().map(|x| *x);
            self.path.push((node, 1));
        }
        curr
    }
}

/// Iterator for traversing all [MiniscriptKey]'s in AST starting from some specific node which
/// constructs the iterator via [Miniscript::iter_pubkeys] method.
pub struct PubkeyIter<'a, Pk: 'a + MiniscriptKey, Ctx: ScriptContext> {
    node_iter: Iter<'a, Pk, Ctx>,
    keys_buff: VecDeque<Pk>,
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> PubkeyIter<'a, Pk, Ctx> {
    fn new(miniscript: &'a Miniscript<Pk, Ctx>) -> Self {
        PubkeyIter {
            node_iter: Iter::new(miniscript),
            keys_buff: VecDeque::new(),
        }
    }
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> Iterator for PubkeyIter<'a, Pk, Ctx> {
    type Item = Pk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.keys_buff.is_empty() {
            self.keys_buff = VecDeque::from(loop {
                let data = self.node_iter.next()?.get_pubkeys();
                if !data.is_empty() {
                    break data;
                }
            });
        }
        self.keys_buff.pop_front()
    }
}

/// Iterator for traversing all [MiniscriptKey] hashes in AST starting from some specific node which
/// constructs the iterator via [Miniscript::iter_pubkey_hashes] method.
pub struct PubkeyHashIter<'a, Pk: 'a + MiniscriptKey, Ctx: ScriptContext> {
    node_iter: Iter<'a, Pk, Ctx>,
    keyhashes_buff: VecDeque<Pk::Hash>,
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> PubkeyHashIter<'a, Pk, Ctx> {
    fn new(miniscript: &'a Miniscript<Pk, Ctx>) -> Self {
        PubkeyHashIter {
            node_iter: Iter::new(miniscript),
            keyhashes_buff: VecDeque::new(),
        }
    }
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> Iterator for PubkeyHashIter<'a, Pk, Ctx> {
    type Item = Pk::Hash;

    fn next(&mut self) -> Option<Self::Item> {
        if self.keyhashes_buff.is_empty() {
            self.keyhashes_buff = VecDeque::from(loop {
                let data = self.node_iter.next()?.get_pubkey_hashes();
                if !data.is_empty() {
                    break data;
                }
            });
        }
        self.keyhashes_buff.pop_front()
    }
}

/// Enum representing either key or a key hash value coming from a miniscript item inside AST
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PubkeyOrHash<Pk: MiniscriptKey> {
    /// Plain public key
    PlainPubkey(Pk),
    /// Hashed public key
    HashedPubkey(Pk::Hash),
}

/// Iterator for traversing all [MiniscriptKey]'s and hashes, depending what data are present in AST,
/// starting from some specific node which constructs the iterator via
/// [Miniscript::iter_keys_and_hashes] method.
pub struct PubkeyAndHashIter<'a, Pk: 'a + MiniscriptKey, Ctx: ScriptContext> {
    node_iter: Iter<'a, Pk, Ctx>,
    buff: VecDeque<PubkeyOrHash<Pk>>,
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> PubkeyAndHashIter<'a, Pk, Ctx> {
    fn new(miniscript: &'a Miniscript<Pk, Ctx>) -> Self {
        PubkeyAndHashIter {
            node_iter: Iter::new(miniscript),
            buff: VecDeque::new(),
        }
    }

    /// Returns a `Option`, listing all public keys found in AST starting from this
    /// `Miniscript` item, or `None` signifying that at least one key hash was found, making
    /// impossible to enumerate all source public keys from the script.
    ///
    /// * Differs from `Miniscript::iter_pubkeys().collect()` in the way that this function fails on
    ///   the first met public key hash, while [PubkeysIter] just ignores them.
    /// * Differs from `Miniscript::iter_pubkeys_and_hashes().collect()` in the way that it lists
    ///   only public keys, and not their hashes
    ///
    /// Unlike these functions, [pubkeys_only] returns an `Option` value with `Vec`, not an iterator,
    /// and consumes the iterator object.
    pub fn pubkeys_only(mut self) -> Option<Vec<Pk>> {
        self.try_fold(Vec::<Pk>::new(), |mut keys, item| match item {
            PubkeyOrHash::HashedPubkey(_) => None,
            PubkeyOrHash::PlainPubkey(key) => {
                keys.push(key);
                Some(keys)
            }
        })
    }
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> Iterator for PubkeyAndHashIter<'a, Pk, Ctx> {
    type Item = PubkeyOrHash<Pk>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buff.is_empty() {
            self.buff = VecDeque::from(loop {
                let data = self.node_iter.next()?.get_pubkeys_and_hashes();
                if !data.is_empty() {
                    break data;
                }
            });
        }
        self.buff.pop_front()
    }
}

// Module is public since it export testcase generation which may be used in
// dependent libraries for their own tasts based on Miniscript AST
#[cfg(test)]
pub mod test {
    use super::{Miniscript, MiniscriptKey};
    use bitcoin;
    use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
    use bitcoin::util::address::AddressType::P2pkh;
    use bitcoin::{secp256k1, PublicKey};
    use miniscript::iter::PubkeyOrHash;
    use std::collections::HashSet;
    use std::str::FromStr;

    pub type TestData = (
        Miniscript<bitcoin::PublicKey>,
        Vec<bitcoin::PublicKey>,
        Vec<hash160::Hash>,
        bool, // Indicates that the top-level contains public key or hashes
    );

    pub fn gen_secp_pubkeys(n: usize) -> Vec<secp256k1::PublicKey> {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];

        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            ret.push(secp256k1::PublicKey::from_secret_key(
                &secp,
                &secp256k1::SecretKey::from_slice(&sk[..]).unwrap(),
            ));
        }
        ret
    }

    pub fn gen_bitcoin_pubkeys(n: usize, compressed: bool) -> Vec<bitcoin::PublicKey> {
        gen_secp_pubkeys(n)
            .into_iter()
            .map(|key| bitcoin::PublicKey { key, compressed })
            .collect()
    }

    pub fn gen_testcases() -> Vec<TestData> {
        let k = gen_bitcoin_pubkeys(10, true);
        let h: Vec<hash160::Hash> = k
            .iter()
            .map(|pk| hash160::Hash::hash(&pk.to_bytes()))
            .collect();

        let preimage = vec![0xab as u8; 32];
        let sha256_hash = sha256::Hash::hash(&preimage);
        let sha256d_hash_rev = sha256d::Hash::hash(&preimage);
        let mut sha256d_hash_bytes = sha256d_hash_rev.clone().into_inner();
        sha256d_hash_bytes.reverse();
        let sha256d_hash = sha256d::Hash::from_inner(sha256d_hash_bytes);
        let hash160_hash = hash160::Hash::hash(&preimage);
        let ripemd160_hash = ripemd160::Hash::hash(&preimage);

        vec![
            (ms_str!("after({})", 1000), vec![], vec![], false),
            (ms_str!("older({})", 1000), vec![], vec![], false),
            (ms_str!("sha256({})", sha256_hash), vec![], vec![], false),
            (ms_str!("hash256({})", sha256d_hash), vec![], vec![], false),
            (ms_str!("hash160({})", hash160_hash), vec![], vec![], false),
            (
                ms_str!("ripemd160({})", ripemd160_hash),
                vec![],
                vec![],
                false,
            ),
            (ms_str!("c:pk_k({})", k[0]), vec![k[0]], vec![], true),
            (ms_str!("c:pk_h({})", h[6]), vec![], vec![h[6]], true),
            (
                ms_str!("and_v(vc:pk_k({}),c:pk_h({}))", k[0], h[1]),
                vec![k[0]],
                vec![h[1]],
                false,
            ),
            (
                ms_str!("and_b(c:pk_k({}),sjtv:sha256({}))", k[0], sha256_hash),
                vec![k[0]],
                vec![],
                false,
            ),
            (
                ms_str!(
                    "andor(c:pk_k({}),jtv:sha256({}),c:pk_h({}))",
                    k[1],
                    sha256_hash,
                    h[2]
                ),
                vec![k[1]],
                vec![h[2]],
                false,
            ),
            (
                ms_str!("multi(3,{},{},{},{},{})", k[9], k[8], k[7], k[0], k[1]),
                vec![k[9], k[8], k[7], k[0], k[1]],
                vec![],
                true,
            ),
            (
                ms_str!(
                    "thresh(3,c:pk_k({}),sc:pk_k({}),sc:pk_k({}),sc:pk_k({}),sc:pk_k({}))",
                    k[2],
                    k[3],
                    k[4],
                    k[5],
                    k[6]
                ),
                vec![k[2], k[3], k[4], k[5], k[6]],
                vec![],
                false,
            ),
            (
                ms_str!(
                    "or_d(multi(2,{},{}),and_v(v:multi(2,{},{}),older(10000)))",
                    k[6],
                    k[7],
                    k[8],
                    k[9]
                ),
                vec![k[6], k[7], k[8], k[9]],
                vec![],
                false,
            ),
            (
                ms_str!(
                    "or_d(multi(3,{},{},{},{},{}),\
                      and_v(v:thresh(2,c:pk_h({}),\
                      ac:pk_h({}),ac:pk_h({})),older(10000)))",
                    k[0],
                    k[2],
                    k[4],
                    k[6],
                    k[9],
                    h[8],
                    h[7],
                    h[0]
                ),
                vec![k[0], k[2], k[4], k[6], k[9]],
                vec![h[8], h[7], h[0]],
                false,
            ),
        ]
    }

    #[test]
    fn get_keys() {
        gen_testcases()
            .into_iter()
            .enumerate()
            .for_each(|(idx, (ms, k, h, test_top_level))| {
                if !test_top_level {
                    return;
                }
                println!("Test case {}: {:?}", idx + 1, ms);
                let ms = *ms.branches().first().unwrap_or(&&ms);
                assert_eq!(ms.get_pubkeys(), k);
            })
    }

    #[test]
    fn get_hashes() {
        gen_testcases()
            .into_iter()
            .enumerate()
            .for_each(|(idx, (ms, k, h, test_top_level))| {
                if !test_top_level {
                    return;
                }
                println!("Test case {}: {:?}", idx + 1, ms);
                let ms = *ms.branches().first().unwrap_or(&&ms);
                let mut all: Vec<hash160::Hash> = k
                    .iter()
                    .map(|p| hash160::Hash::hash(&p.to_bytes()))
                    .collect();
                // In our test cases we always have plain keys going first
                all.extend(h);
                assert_eq!(ms.get_pubkey_hashes(), all);
            })
    }

    #[test]
    fn get_pubkey_and_hashes() {
        gen_testcases()
            .into_iter()
            .enumerate()
            .for_each(|(idx, (ms, k, h, test_top_level))| {
                if !test_top_level {
                    return;
                }
                println!("Test case {}: {:?}", idx + 1, ms);
                let ms = *ms.branches().first().unwrap_or(&&ms);
                let r: Vec<PubkeyOrHash<bitcoin::PublicKey>> = if k.is_empty() {
                    h.into_iter()
                        .map(|h| PubkeyOrHash::HashedPubkey(h))
                        .collect()
                } else {
                    k.into_iter()
                        .map(|k| PubkeyOrHash::PlainPubkey(k))
                        .collect()
                };
                assert_eq!(ms.get_pubkeys_and_hashes(), r);
            })
    }

    #[test]
    fn find_keys() {
        gen_testcases()
            .into_iter()
            .enumerate()
            .for_each(|(idx, (ms, k, _, _))| {
                println!("Test case {}: {:?}", idx + 1, ms);
                assert_eq!(ms.iter_pubkeys().collect::<Vec<bitcoin::PublicKey>>(), k);
            })
    }

    #[test]
    fn find_hashes() {
        gen_testcases()
            .into_iter()
            .enumerate()
            .for_each(|(idx, (ms, k, h, _))| {
                println!("Test case {}: {:?}", idx + 1, ms);
                let mut all: Vec<hash160::Hash> = k
                    .iter()
                    .map(|p| hash160::Hash::hash(&p.to_bytes()))
                    .collect();
                // In our test cases we always have plain keys going first
                all.extend(h);
                assert_eq!(ms.iter_pubkey_hashes().collect::<Vec<hash160::Hash>>(), all);
            })
    }

    #[test]
    fn find_pubkeys_and_hashes() {
        gen_testcases()
            .into_iter()
            .enumerate()
            .for_each(|(idx, (ms, k, h, _))| {
                println!("Test case {}: {:?}", idx + 1, ms);
                let mut all: Vec<PubkeyOrHash<bitcoin::PublicKey>> = k
                    .into_iter()
                    .map(|k| PubkeyOrHash::PlainPubkey(k))
                    .collect();
                all.extend(h.into_iter().map(|h| PubkeyOrHash::HashedPubkey(h)));
                assert_eq!(
                    ms.iter_pubkeys_and_hashes()
                        .collect::<Vec<PubkeyOrHash<bitcoin::PublicKey>>>(),
                    all
                );
            })
    }

    #[test]
    fn replace_pubkeys_and_hashes() {
        gen_testcases()
            .into_iter()
            .enumerate()
            .for_each(|(idx, (ms, k, h, _))| {
                if k.is_empty() && h.is_empty() {
                    return;
                }
                println!("Test case {}: {:?}", idx + 1, ms);
                let mut all: Vec<PubkeyOrHash<bitcoin::PublicKey>> = k
                    .into_iter()
                    .map(|k| PubkeyOrHash::PlainPubkey(k))
                    .collect();
                all.extend(h.into_iter().map(|h| PubkeyOrHash::HashedPubkey(h)));
                // Taking next keys
                let gen = gen_bitcoin_pubkeys(20, true)[10..20].to_vec();
                let new: Vec<PubkeyOrHash<bitcoin::PublicKey>> = all
                    .iter()
                    .enumerate()
                    .map(|(index, item)| match item {
                        PubkeyOrHash::PlainPubkey(_) => PubkeyOrHash::PlainPubkey(gen[index]),
                        PubkeyOrHash::HashedPubkey(_) => {
                            PubkeyOrHash::HashedPubkey(hash160::Hash::hash(&gen[index].to_bytes()))
                        }
                    })
                    .collect();
                let replaced = ms
                    .replace_pubkeys_and_hashes(&|item| {
                        let index = all.iter().position(|i| *i == item).unwrap();
                        match item {
                            PubkeyOrHash::PlainPubkey(pk) => Some(new[index].clone()),
                            PubkeyOrHash::HashedPubkey(pkh) => Some(new[index].clone()),
                        }
                    })
                    .unwrap();
                assert_eq!(
                    replaced
                        .iter_pubkeys_and_hashes()
                        .collect::<Vec<PubkeyOrHash<bitcoin::PublicKey>>>(),
                    new
                );
            })
    }
}
