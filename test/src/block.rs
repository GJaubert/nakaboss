use std::collections::HashMap;

use nakamoto_common::bitcoin::blockdata::transaction::{OutPoint, TxOut};

pub use nakamoto_common::block::*;

/// Solve a block's proof of work puzzle.
pub fn solve(header: &mut Header) {
    let target = header.target();
    while header.validate_pow(target).is_err() {
        header.nonce = header.nonce.wrapping_add(1);
    }
}

pub mod cache {
    pub mod model;
}

#[derive(Default)]
struct UtxoSet {
    utxos: HashMap<OutPoint, TxOut>,
}

impl std::ops::Deref for UtxoSet {
    type Target = HashMap<OutPoint, TxOut>;

    fn deref(&self) -> &Self::Target {
        &self.utxos
    }
}

impl std::ops::DerefMut for UtxoSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.utxos
    }
}

impl UtxoSet {
    fn apply(&mut self, tx: &Transaction) {
        if !tx.is_coinbase() {
            for input in tx.input.iter() {
                if self.utxos.remove(&input.previous_output).is_none() {
                    return;
                }
            }
        }

        for (vout, output) in tx.output.iter().enumerate() {
            let out = OutPoint {
                txid: tx.compute_txid(),
                vout: vout as u32,
            };
            self.utxos.insert(out, output.clone());
        }
    }
}

pub mod gen {
    use std::collections::HashMap;

    use bitcoin::bip158;
    use bitcoin::blockdata::script::Script;
    use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
    use bitcoin::consensus::Decodable;
    use bitcoin::hash_types::{TxMerkleNode, Txid};
    use bitcoin::PubkeyHash;

    use nakamoto_common::bitcoin::hashes::Hash;
    use nakamoto_common::bitcoin::transaction::Version;
    use nakamoto_common::bitcoin::{
        self, absolute::LockTime, blockdata, merkle_tree, Amount, ScriptBuf, Sequence, Witness,
    };
    use nakamoto_common::bitcoin_hashes::hash160;
    use nakamoto_common::bitcoin_num::uint::Uint256;
    use nakamoto_common::block::filter::{BlockFilter, FilterHash, FilterHeader};
    use nakamoto_common::block::*;
    use nakamoto_common::nonempty::NonEmpty;

    use super::UtxoSet;

    /// Generates a random transaction.
    pub fn transaction(rng: &mut fastrand::Rng) -> Transaction {
        let mut input = Vec::with_capacity(rng.usize(1..8));
        let mut output = Vec::with_capacity(rng.usize(1..8));

        // Inputs.
        for _ in 0..input.capacity() {
            let bytes = std::iter::repeat_with(|| rng.u8(..))
                .take(32)
                .collect::<Vec<_>>();

            let txid = Txid::from_slice(&bytes).unwrap();
            let inp = TxIn {
                previous_output: OutPoint {
                    txid,
                    vout: rng.u32(0..16),
                },
                script_sig: ScriptBuf::from(Script::new()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            };
            input.push(inp);
        }

        // Outputs.
        for _ in 0..output.capacity() {
            let out = tx_out(rng);
            output.push(out);
        }

        Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input,
            output,
        }
    }

    /// Generates a random transaction with the specified input and value.
    pub fn transaction_with(
        previous_output: OutPoint,
        value: u64,
        rng: &mut fastrand::Rng,
    ) -> Transaction {
        assert!(value > 0);

        let mut output = Vec::with_capacity(rng.usize(1..8));
        let input = TxIn {
            previous_output,
            script_sig: ScriptBuf::from(Script::new()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        let fee = rng.u64(0..value);
        let mut allowance = value - fee;

        // Outputs.
        for _ in 0..output.capacity() {
            let script_pubkey = script(rng);
            let v = rng.u64(1..=allowance);

            output.push(TxOut {
                value: Amount::from_sat(v),
                script_pubkey: script_pubkey.into_script_buf(),
            });

            allowance -= v;
            if allowance == 0 {
                break;
            }
        }
        assert!(output.iter().map(|o| o.value.to_sat()).sum::<u64>() <= value);

        Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![input],
            output,
        }
    }

    pub fn script(rng: &mut fastrand::Rng) -> Box<Script> {
        let bytes = std::iter::repeat_with(|| rng.u8(..))
            .take(20)
            .collect::<Vec<_>>();
        let hash = hash160::Hash::from_slice(bytes.as_slice()).unwrap();
        let pkh = PubkeyHash::from_raw_hash(hash);

        ScriptBuf::new_p2pkh(&pkh).into_boxed_script()
    }

    /// Generate a random transaction output.
    pub fn tx_out(rng: &mut fastrand::Rng) -> TxOut {
        let script_pubkey = script(rng);

        TxOut {
            value: Amount::from_sat(rng.u64(1..100_000_000)),
            script_pubkey: script_pubkey.into_script_buf(),
        }
    }

    /// Generate a random coinbase transaction.
    pub fn coinbase(rng: &mut fastrand::Rng) -> Transaction {
        let output = vec![tx_out(rng)];

        let input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from(Script::new()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![input],
            output,
        }
    }

    /// Generate a random block based on a previous header.
    pub fn block(prev_header: &Header, rng: &mut fastrand::Rng) -> Block {
        let mut txdata = Vec::with_capacity(rng.usize(1..16));
        txdata.push(coinbase(rng));
        for _ in 1..txdata.capacity() {
            txdata.push(transaction(rng));
        }
        self::block_with(prev_header, txdata, rng)
    }

    /// Generate a random block based on a previous header.
    pub fn block_with(
        prev_header: &Header,
        txdata: Vec<Transaction>,
        rng: &mut fastrand::Rng,
    ) -> Block {
        let hashes = txdata.iter().map(|obj| obj.compute_txid().to_raw_hash());
        let merkle_root = merkle_tree::calculate_root(hashes);
        let merkle_root = match merkle_root {
            Some(hash) => TxMerkleNode::from_raw_hash(hash),
            _ => TxMerkleNode::all_zeros(),
        };
        let header = header(prev_header, merkle_root, rng);

        Block { header, txdata }
    }

    /// Generate a random header based on a previous header and merkle root.
    pub fn header(
        prev_header: &Header,
        merkle_root: TxMerkleNode,
        rng: &mut fastrand::Rng,
    ) -> Header {
        let target_spacing = 60 * 10; // 10 minutes.
        let delta = rng.u32(target_spacing - 60..target_spacing + 60);

        let time = prev_header.time + delta;
        let bits = prev_header.target().to_compact_lossy();

        let mut header = Header {
            version: blockdata::block::Version::ONE,
            time,
            nonce: rng.u32(..),
            bits,
            merkle_root,
            prev_blockhash: prev_header.block_hash(),
        };
        super::solve(&mut header);

        header
    }

    /// Generate a random minimum-difficulty genesis block.
    pub fn genesis(rng: &mut fastrand::Rng) -> Block {
        let txdata = vec![coinbase(rng)];
        let hashes = txdata.iter().map(|obj| obj.compute_txid().to_raw_hash());
        let merkle_root = merkle_tree::calculate_root(hashes);
        let merkle_root = match merkle_root {
            Some(hash) => TxMerkleNode::from_raw_hash(hash),
            _ => TxMerkleNode::all_zeros(),
        };

        let target = Uint256([
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0x7fffffffffffffffu64,
        ]);
        let target = nakamoto_common::block::tree::convert_to_bitcoin_target(target);
        let bits = target.to_compact_lossy();

        let mut header = Header {
            version: blockdata::block::Version::ONE,
            time: 0,
            nonce: 0,
            bits,
            merkle_root,
            prev_blockhash: BlockHash::all_zeros(),
        };
        super::solve(&mut header);

        Block { header, txdata }
    }

    /// Generate a random blockchain.
    pub fn blockchain(parent: Block, height: Height, rng: &mut fastrand::Rng) -> NonEmpty<Block> {
        let mut prev_header = parent.header;
        let mut chain = NonEmpty::new(parent.clone());
        let mut utxos = UtxoSet::default();

        assert!(height > 0);
        assert!(!parent.txdata.is_empty());

        for tx in &parent.txdata {
            utxos.apply(tx);
        }

        for _ in 0..height {
            let mut txdata = Vec::with_capacity(rng.usize(1..16));
            let mut outpoints = utxos
                .iter()
                .map(|(k, txout)| (*k, txout.value))
                .collect::<Vec<_>>();

            for _ in 0..txdata.capacity() {
                if let Some((out, value)) = outpoints.pop() {
                    let tx = transaction_with(out, value.to_sat(), rng);
                    assert!(!tx.output.is_empty());

                    utxos.apply(&tx);
                    txdata.push(tx);
                } else {
                    break;
                }
            }

            let block = block_with(&prev_header, txdata, rng);
            prev_header = block.header;

            chain.push(block);
        }
        chain
    }

    /// Generate a fork from a fork block.
    pub fn fork(parent: &Header, length: usize, rng: &mut fastrand::Rng) -> Vec<Block> {
        let mut prev_header = *parent;
        let mut chain = Vec::new();

        assert!(length > 0);

        for _ in 0..length {
            let block = block(&prev_header, rng);
            prev_header = block.header;

            chain.push(block);
        }
        chain
    }

    /// Generate a random header chain.
    pub fn headers(parent: Header, height: Height, rng: &mut fastrand::Rng) -> NonEmpty<Header> {
        let mut prev_header = parent;
        let mut chain = NonEmpty::new(parent);

        assert!(height > 0);

        for _ in 0..height {
            let header = header(&prev_header, TxMerkleNode::all_zeros(), rng);
            prev_header = header;

            chain.push(header);
        }
        chain
    }

    /// Create a filter from a block.
    pub fn cfilter(block: &Block) -> BlockFilter {
        let mut txmap = HashMap::new();
        for tx in block.txdata.iter().skip(1) {
            for input in tx.input.iter() {
                txmap.insert(input.previous_output, input.script_sig.clone());
            }
        }

        BlockFilter::new_script_filter(block, |out| {
            if let Some(s) = txmap.get(out) {
                Ok(s.clone())
            } else {
                Err(bip158::Error::UtxoMissing(*out))
            }
        })
        .unwrap()
    }

    /// Create a filter header from a previous header and a filter.
    pub fn cfheader(parent: &FilterHeader, cfilter: &BlockFilter) -> (FilterHash, FilterHeader) {
        let hash = FilterHash::hash(&cfilter.content);
        let header = hash.filter_header(parent);

        (hash, header)
    }

    /// Build a filter header chain from input blocks.
    pub fn cfheaders_from_blocks<'a>(
        mut parent: FilterHeader,
        blocks: impl Iterator<Item = &'a Block>,
    ) -> Vec<(FilterHash, FilterHeader)> {
        let mut cfheaders = Vec::new();

        for blk in blocks {
            let (cfhash, cfheader) = cfheader(&parent, &cfilter(blk));
            cfheaders.push((cfhash, cfheader));
            parent = cfheader;
        }
        cfheaders
    }

    /// Build filters from blocks.
    pub fn cfilters<'a>(
        blocks: impl Iterator<Item = &'a Block> + 'a,
    ) -> impl Iterator<Item = BlockFilter> + 'a {
        blocks.map(cfilter)
    }

    /// Generates a random filter header chain starting from a parent filter header.
    pub fn cfheaders(
        mut parent: FilterHeader,
        rng: &'_ mut fastrand::Rng,
    ) -> impl Iterator<Item = (FilterHash, FilterHeader)> + '_ {
        std::iter::repeat_with(move || {
            let bytes = std::iter::repeat_with(|| rng.u8(..))
                .take(32)
                .collect::<Vec<_>>();
            let hash = FilterHash::consensus_decode(&mut bytes.as_slice()).unwrap();
            let header = hash.filter_header(&parent);

            parent = header;

            (hash, header)
        })
    }

    /// Generate a random set of scripts to watch, given a blockchain and birth height.
    pub fn watchlist_rng<'a>(
        birth: Height,
        chain: impl Iterator<Item = &'a Block>,
        rng: &mut fastrand::Rng,
    ) -> (Vec<Box<Script>>, Vec<Height>, u64) {
        let mut watchlist = Vec::new();
        let mut blocks = Vec::new();
        let mut balance = 0;

        for (h, blk) in chain.enumerate().skip(birth as usize) {
            // Randomly pick certain blocks.
            if rng.bool() {
                // Randomly pick a transaction and add its output to the watchlist.
                let tx = &blk.txdata[rng.usize(0..blk.txdata.len())];
                let out = &tx.output[rng.usize(0..tx.output.len())];

                watchlist.push(out.script_pubkey.clone().into_boxed_script());
                blocks.push(h as Height);
                balance += out.value.to_sat();
            }
        }
        (watchlist, blocks, balance)
    }

    /// Generate a set of scripts to watch, given a blockchain and birth height.
    pub fn watchlist<'a>(
        birth: Height,
        chain: impl Iterator<Item = &'a Block>,
    ) -> (Vec<Box<Script>>, u64) {
        let mut watchlist = Vec::new();
        let mut balance = 0;

        for blk in chain.skip(birth as usize) {
            let tx = &blk.txdata[0];
            let out = &tx.output[0];

            watchlist.push(out.script_pubkey.clone().into_boxed_script());
            balance += out.value.to_sat();
        }
        (watchlist, balance)
    }
}
