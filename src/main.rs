use concread::CowCell;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sp_core::{
    crypto::{AccountId32, Ss58AddressFormat, Ss58Codec},
    sr25519::Pair,
    DeriveJunction, Pair as PairTrait,
};
use structopt::StructOpt;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};

#[derive(StructOpt, Debug)]
struct Options {
    #[structopt(long, help = "Desired prefix of the address")]
    prefix: String,

    #[structopt(long, help = "Prefix for the secret seed", default_value = "//")]
    seed_prefix: String,

    #[structopt(long, help = "Should we check for case")]
    only_case_sensitive: bool,
}

impl Options {
    fn address(&self, pair: &Pair) -> String {
        AccountId32::from(pair.public()).to_ss58check_with_version(Ss58AddressFormat::Custom(42))
    }

    pub fn to_candidate(&self, (pair, seed): (Pair, String)) -> Candidate {
        Candidate {
            address: self.address(&pair),
            pair,
            seed,
        }
    }

    pub fn pair_is_better(&self, pair: &Pair, best_so_far: &Option<Candidate>) -> bool {
        match best_so_far {
            Some(b) => self.is_better(&self.address(pair), &b.address),
            None => true,
        }
    }

    pub fn is_better(&self, new: &str, old: &str) -> bool {
        match self
            .loose_prefix_match(new)
            .cmp(&self.loose_prefix_match(old))
        {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }

        match self.match_count(new).cmp(&self.match_count(old)) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }

        false
    }

    fn loose_prefix_match(&self, other: &str) -> usize {
        if self.only_case_sensitive {
            matching_prefix_length(&self.prefix, other)
        } else {
            matching_prefix_length(&self.prefix.to_lowercase(), &other.to_lowercase())
        }
    }

    fn match_count(&self, other: &str) -> usize {
        self.prefix
            .chars()
            .zip(other.chars())
            .filter(|(a, b)| a == b)
            .count()
    }

    fn is_perfect_match(&self, candidate: &Candidate) -> bool {
        candidate.address.starts_with(&self.prefix)
    }
}

fn matching_prefix_length(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(a, b)| a == b).count()
}

fn main() {
    let options = Arc::new(Options::from_args());

    let should_continue = Arc::new(AtomicBool::new(true));

    let best_so_far = Arc::new(CowCell::new(None));
    let (better_tx, better_rx) = mpsc::sync_channel(10);

    let thread = {
        let best_so_far = best_so_far.clone();
        let better_tx = better_tx.clone();
        let options = options.clone();
        let should_continue = should_continue.clone();
        std::thread::spawn(move || {
            let base_secret = rand::random::<[u64; 3]>();
            let base_seed = format!(
                "{}/{}/{}/{}",
                &options.seed_prefix, base_secret[0], base_secret[1], base_secret[2]
            );
            let base_pair = Pair::from_string(&base_seed, None).unwrap();

            let n_offset = rand::random::<u64>();
            (0..u64::MAX)
                .into_par_iter()
                .map(|n| match should_continue.load(Ordering::Relaxed) {
                    true => Some(n.wrapping_add(n_offset)),
                    false => None,
                })
                .while_some()
                .map(|n| {
                    let derived = base_pair
                        .derive(core::iter::once(DeriveJunction::soft(n)), None)
                        .unwrap()
                        .0;
                    (derived, n)
                })
                .filter(|pair| options.pair_is_better(&pair.0, &best_so_far.read()))
                .for_each(|(pair, n)| {
                    let seed = format!("{}/{}", base_seed, n);
                    better_tx.send((pair, seed)).unwrap()
                });
        })
    };
    drop(better_tx);

    better_rx
        .iter()
        .filter(|pair| options.pair_is_better(&pair.0, &best_so_far.read()))
        .for_each(|pair| {
            let candidate = options.to_candidate(pair);
            candidate.display();

            if options.is_perfect_match(&candidate) {
                should_continue.store(false, Ordering::Relaxed);
            }

            let mut write_txn = best_so_far.write();
            *write_txn = Some(candidate);
            write_txn.commit();
        });
    thread.join().unwrap();
}

#[derive(Clone)]
struct Candidate {
    address: String,
    pair: Pair,
    seed: String,
}

impl Candidate {
    fn display(&self) {
        println!("{}\n    {}", self.address, self.seed);
    }
}
