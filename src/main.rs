use concread::CowCell;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sp_core::{
    crypto::{AccountId32, SecretStringError, Ss58AddressFormat, Ss58Codec},
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

    #[structopt(long, help = "Prefix for the secret seed", default_value = "")]
    seed_prefix: String,

    #[structopt(long, help = "Should we check for case")]
    only_case_sensitive: bool,

    #[structopt(
        long,
        help = "Which scheme to generate keys for",
        default_value = "Sr25519"
    )]
    scheme: Scheme,
}

#[derive(Debug, Clone, Copy)]
enum Scheme {
    Sr25519,
    Ed25519,
}

impl std::str::FromStr for Scheme {
    type Err = String;

    fn from_str(scheme: &str) -> Result<Self, Self::Err> {
        match scheme.to_lowercase().as_ref() {
            "sr25519" => Ok(Scheme::Sr25519),
            "eddsa" | "ed25519" => Ok(Scheme::Ed25519),
            _ => Err(format!("Unrecognized Scheme: {}", scheme)),
        }
    }
}

#[derive(Clone)]
enum SchemedPair {
    Sr25519(sp_core::sr25519::Pair),
    Ed25519(sp_core::ed25519::Pair),
}

impl SchemedPair {
    fn account_id(&self) -> AccountId32 {
        match self {
            SchemedPair::Sr25519(p) => AccountId32::from(p.public()),
            SchemedPair::Ed25519(p) => AccountId32::from(p.public()),
        }
    }

    fn derive(&self, n: u64) -> Self {
        match &self {
            SchemedPair::Sr25519(p) => SchemedPair::Sr25519(
                p.derive(core::iter::once(DeriveJunction::hard(n)), None)
                    .unwrap_or_else(|infallible| match infallible {})
                    .0,
            ),
            SchemedPair::Ed25519(p) => SchemedPair::Ed25519(
                p.derive(core::iter::once(DeriveJunction::hard(n)), None)
                    .unwrap_or_else(|_| unreachable!("known no soft junctions"))
                    .0,
            ),
        }
    }
}

impl Options {
    pub fn is_better(&self, candidate: &Candidate, best_so_far: &Option<Candidate>) -> bool {
        match best_so_far {
            Some(b) => self.str_is_better(&candidate.address, &b.address),
            None => true,
        }
    }

    pub fn str_is_better(&self, new: &str, old: &str) -> bool {
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
    let throughput = Arc::new(Throughput::default());

    let best_so_far = Arc::new(CowCell::new(None));
    let (better_tx, better_rx) = mpsc::sync_channel(10);

    let base_candidate =
        Candidate::base(options.scheme, &options.seed_prefix, rand::random()).unwrap();

    let thread = {
        let best_so_far = best_so_far.clone();
        let better_tx = better_tx.clone();
        let options = options.clone();
        let should_continue = should_continue.clone();
        let throughput = throughput.clone();
        std::thread::spawn(move || {
            let n_offset = rand::random::<u32>();
            (0..u32::MAX)
                .into_par_iter()
                .map(|n| match should_continue.load(Ordering::Relaxed) {
                    true => Some(n.wrapping_add(n_offset)),
                    false => None,
                })
                .while_some()
                .inspect(|_| throughput.increment())
                .map(|n| base_candidate.derive(n))
                .filter(|candidate| options.is_better(&candidate, &best_so_far.read()))
                .for_each(|candidate| better_tx.send(candidate).unwrap());
        })
    };
    drop(better_tx);

    let monitor_thread = {
        let throughput = throughput.clone();
        let should_continue = should_continue.clone();
        std::thread::spawn(move || {
            if !atty::is(atty::Stream::Stdout) {
                return;
            }

            while should_continue.load(Ordering::Relaxed) {
                eprint!("\rAddresses: {} / s", throughput.take());
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        })
    };

    better_rx
        .iter()
        .filter(|candidate| options.is_better(&candidate, &best_so_far.read()))
        .for_each(|candidate| {
            eprintln!("\rFound new best:               ");
            eprintln!("{}\n    {}", candidate.address, candidate.seed);

            if options.is_perfect_match(&candidate) {
                should_continue.store(false, Ordering::Relaxed);
                println!("{}", candidate.seed);
            }

            let mut write_txn = best_so_far.write();
            *write_txn = Some(candidate);
            write_txn.commit();
        });
    thread.join().unwrap();
    monitor_thread.join().unwrap();
}

#[derive(Clone)]
struct Candidate {
    address: String,
    pair: SchemedPair,
    seed: String,
}

impl Candidate {
    fn base(scheme: Scheme, seed: &str, secret: [u32; 7]) -> Result<Self, SecretStringError> {
        let bytes_suffix = secret
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("//");
        let seed = format!("{}//{}", &seed, bytes_suffix);

        let pair = match scheme {
            Scheme::Sr25519 => {
                SchemedPair::Sr25519(sp_core::sr25519::Pair::from_string(&seed, None)?)
            }
            Scheme::Ed25519 => {
                SchemedPair::Ed25519(sp_core::ed25519::Pair::from_string(&seed, None)?)
            }
        };

        Ok(Candidate::new(pair, seed))
    }

    fn new(pair: SchemedPair, seed: String) -> Candidate {
        Candidate {
            address: pair
                .account_id()
                .to_ss58check_with_version(Ss58AddressFormat::Custom(42)),
            pair,
            seed,
        }
    }

    fn derive(&self, n: u32) -> Candidate {
        let new_pair = self.pair.derive(n.into());
        let seed = format!("{}//{}", self.seed, n);
        Candidate::new(new_pair, seed)
    }
}

#[derive(Default)]
struct Throughput {
    count: std::sync::atomic::AtomicU64,
}

impl Throughput {
    fn take(&self) -> u64 {
        self.count.fetch_min(0, Ordering::Relaxed)
    }

    fn increment(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}
