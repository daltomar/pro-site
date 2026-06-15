use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

const ADJECTIVES: &[&str] = &[
    "amber", "ancient", "arid", "ashen", "azure", "bare", "birch", "bleak", "bold", "brisk",
    "broad", "bronze", "burnished", "calm", "cedar", "clear", "clever", "cobalt", "cold",
    "coral", "crisp", "cyan", "dark", "deep", "dense", "dim", "distant", "dry", "dusky",
    "dull", "early", "earthy", "elder", "emerald", "empty", "even", "eternal", "faint",
    "fallen", "far", "fierce", "final", "firm", "fixed", "flat", "fleeting", "fluid", "fond",
    "free", "fresh", "frozen", "fleet", "gentle", "gilded", "glassy", "golden", "grave",
    "grey", "grim", "harsh", "hazel", "hazy", "hidden", "high", "hollow", "humble", "hushed",
    "icy", "idle", "inner", "iron", "ivory", "jade", "keen", "late", "lean", "level", "light",
    "lime", "lone", "long", "low", "lush", "lunar", "marble", "meek", "mellow", "mild",
    "misty", "muted", "mossy", "naked", "narrow", "near", "nimble", "noble", "north", "oak",
    "ochre", "olden", "onyx", "open", "oval", "pale", "pearl", "pewter", "plain", "placid",
    "polar", "prime", "pure", "primal", "quiet", "rapid", "raw", "regal", "rich", "rigid",
    "rocky", "round", "rough", "rustic", "russet", "sacred", "sage", "salt", "sandy", "scant",
    "serene", "shaded", "sharp", "silent", "silver", "simple", "slate", "slow", "small",
    "smooth", "soft", "solid", "somber", "spare", "sparse", "stark", "steep", "still",
    "stone", "strong", "subtle", "sunlit", "swift", "tall", "tawny", "tender", "tepid",
    "terse", "thin", "thorn", "timber", "tranquil", "true", "twilight", "upper", "vast",
    "veiled", "violet", "vivid", "warm", "wary", "white", "wide", "wild", "winter", "wise",
    "worn", "woven", "ashen", "brisk", "crisp", "dusky", "earthy", "faint", "gilded",
    "hushed", "ivory", "lunar", "mellow", "nimble", "onyx", "pewter", "russet", "somber",
    "tawny", "veiled",
];

const NOUNS: &[&str] = &[
    "anchor", "arch", "arc", "basin", "bay", "beacon", "beam", "blade", "bluff", "boulder",
    "branch", "bridge", "brook", "cairn", "canyon", "cape", "cedar", "chalk", "chasm",
    "chord", "cinder", "cliff", "cloud", "coast", "comet", "creek", "crest", "crown",
    "crystal", "current", "dale", "dawn", "delta", "depth", "desert", "drift", "dune",
    "dusk", "dust", "echo", "edge", "ember", "epoch", "field", "fjord", "flame", "flare",
    "flint", "fog", "ford", "frost", "gable", "gale", "gate", "glacier", "glade", "gorge",
    "grain", "grove", "gulf", "harbor", "haven", "haze", "heath", "helm", "hill", "hollow",
    "horizon", "hull", "inlet", "island", "kelp", "knoll", "lagoon", "lake", "lane", "ledge",
    "lens", "light", "loch", "manor", "marsh", "mesa", "mill", "mist", "moon", "moor",
    "mountain", "mouth", "narrows", "nave", "nest", "notch", "oak", "orbit", "pass", "path",
    "peak", "petal", "pillar", "pine", "plain", "plateau", "plume", "pond", "prairie",
    "prism", "pulse", "quarry", "range", "ravine", "reed", "ridge", "rift", "ring", "river",
    "rock", "roof", "root", "rune", "ruin", "salt", "sand", "shard", "shelf", "shoal",
    "shore", "signal", "slab", "slate", "slope", "sound", "source", "spire", "spring",
    "stone", "strand", "summit", "surge", "swamp", "terrace", "tide", "timber", "torch",
    "tower", "trail", "vale", "valley", "vault", "veil", "vista", "void", "wake", "wall",
    "wave", "well", "wind", "wood", "wisp", "yoke", "zone", "anvil", "axis", "base",
    "cave", "chain", "cistern", "cleft", "col", "crest", "depth", "glacier", "haven",
    "inlet", "kelp", "loch", "mesa", "moat", "nave", "pike", "relic", "rime", "sluice",
    "spur", "strata", "talon", "temple", "tundra", "warden",
];

const PASSWORD_CHARSET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";

static DUMMY_HASH: OnceLock<String> = OnceLock::new();

pub fn init_dummy_hash() {
    DUMMY_HASH.get_or_init(|| {
        hash_password("__dummy_password_for_timing_safety__")
            .expect("Failed to initialise dummy hash")
    });
}

pub fn generate_username() -> String {
    let adj = ADJECTIVES.choose(&mut OsRng).unwrap();
    let noun = NOUNS.choose(&mut OsRng).unwrap();
    format!("{}-{}", adj, noun)
}

pub fn generate_password() -> String {
    let charset_len = PASSWORD_CHARSET.len() as u64;
    (0..14)
        .map(|_| {
            let idx = (OsRng.next_u64() % charset_len) as usize;
            PASSWORD_CHARSET[idx] as char
        })
        .collect()
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

pub fn dummy_verify(password: &str) {
    if let Some(hash) = DUMMY_HASH.get() {
        let _ = verify_password(password, hash);
    }
}

pub fn generate_session_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let raw_token = hex::encode(bytes);
    let hashed_token = hex::encode(Sha256::digest(bytes));
    (raw_token, hashed_token)
}
