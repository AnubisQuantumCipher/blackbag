//! Secret generation, with strength figures that describe the *generator*.
//!
//! # Why nothing here will score a password you typed
//!
//! `log2(charset^length)` is a true statement about a string this module drew
//! uniformly at random. It is not a statement about a string a human chose, and
//! reporting it as one is the lie every strength meter tells: it measures the
//! shape of the characters instead of the process that picked them, so
//! `P@ssw0rd!` is scored as nine characters over a large alphabet rather than
//! as the dictionary entry it is.
//!
//! So [`Strength`] is only ever derived from a *specification*, never from a
//! value, and [`Strength::basis`] states the assumption in words wherever the
//! number is displayed. There is deliberately no function in this module that
//! takes a `&str` and returns bits, and one should not be added: the moment
//! such a figure exists, it gets rendered next to the honest one and the
//! distinction dies.

use anyhow::{bail, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::memlock;
use crate::record::Secret;

/// Longest password we will mint. Well below `MAX_FIELD_BYTES`; the cap exists
/// so a mistyped length cannot ask for a gigabyte of locked memory.
pub const MAX_PASSWORD_LEN: usize = 512;
pub const MAX_PASSPHRASE_WORDS: usize = 64;
pub const MAX_PIN_DIGITS: usize = 32;

pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";

/// Quote, backslash, backtick and space are absent on purpose: these secrets
/// get pasted into shells, YAML and `.env` files by people in a hurry.
pub const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

/// Glyphs that are routinely misread when a secret is copied off a screen or
/// read down a phone. `|` is here because it is confused with `l` and `1`.
pub const AMBIGUOUS: &str = "0O1lI|o";

/// Draws that may be discarded by [`uniform_below`] before it gives up. Each
/// draw is accepted with probability greater than one half, so reaching this
/// bound means the system RNG is malfunctioning, not that we were unlucky.
const MAX_DRAWS: u32 = 256;

/// Whole-password redraws allowed while satisfying the class requirement.
const MAX_CONSTRAINT_ATTEMPTS: u32 = 1000;

/// The embedded wordlist: 512 words, so exactly 9 bits per word.
///
/// Power-of-two by design. It makes the bits-per-word figure exact rather than
/// a rounded logarithm, and it means [`uniform_below`] never has to reject a
/// draw when selecting a word.
///
/// Every entry is 4 to 7 lowercase ASCII letters. The list is sorted and free
/// of duplicates, which is not cosmetic: a duplicated entry would make the true
/// entropy lower than the 9 bits per word this module reports, which is exactly
/// the class of quiet overstatement the module exists to avoid. The invariant
/// is asserted in the tests rather than trusted.
pub const WORDS: [&str; 512] = [
    "able", "acre", "adapt", "afraid", "agree", "album", "alley", "alone",
    "alter", "among", "anger", "annual", "apart", "arbor", "arena", "army",
    "artist", "atom", "audio", "author", "awake", "awning", "badge", "bamboo",
    "barge", "basil", "baton", "bean", "beetle", "behind", "best", "binder",
    "bitter", "blaze", "block", "blur", "boil", "book", "bottle", "boxer",
    "branch", "brick", "bring", "broom", "bubble", "bugle", "bunker", "butter",
    "cable", "calm", "canal", "canvas", "carbon", "carrot", "castle", "cause",
    "cement", "chalk", "charm", "cheer", "chief", "chisel", "chrome", "circle",
    "clamp", "clear", "clinic", "cloud", "clutch", "coffee", "color", "comfort",
    "compass", "cone", "console", "copper", "costume", "counter", "coyote", "crane",
    "credit", "cricket", "cross", "crunch", "cuckoo", "curl", "cushion", "dagger",
    "damage", "daring", "decade", "declare", "deep", "degree", "denim", "deposit",
    "design", "device", "diary", "differ", "dilute", "dispute", "dock", "domain",
    "double", "draft", "draw", "drink", "drum", "dune", "dusty", "eager",
    "earth", "economy", "effort", "elbow", "eleven", "emblem", "emotion", "enable",
    "endorse", "engage", "enough", "entire", "equip", "essay", "evening", "exceed",
    "exhale", "expert", "express", "fabric", "fade", "famous", "farm", "fatigue",
    "feast", "fern", "fiber", "fierce", "finch", "fishing", "flank", "fleet",
    "flint", "flour", "foam", "foil", "fond", "forest", "format", "foster",
    "free", "frog", "fruit", "fume", "furnace", "gadget", "gallon", "garlic",
    "gauge", "gender", "geyser", "ginger", "glad", "gleam", "glove", "goat",
    "goose", "grab", "grand", "grass", "green", "grin", "ground", "guard",
    "guitar", "gutter", "hammer", "harbor", "haste", "hazel", "heart", "height",
    "help", "hidden", "hinge", "hobby", "holiday", "honey", "hook", "horse",
    "house", "humid", "hurdle", "hustle", "icon", "igloo", "impulse", "income",
    "infant", "injure", "input", "insight", "intend", "iris", "issue", "jaguar",
    "jelly", "jigsaw", "joke", "juice", "june", "jury", "keep", "kettle",
    "king", "kitten", "knight", "knot", "labor", "lamb", "lantern", "large",
    "later", "layer", "league", "leather", "legacy", "lemur", "leopard", "library",
    "light", "lime", "link", "listen", "lizard", "locate", "loft", "loop",
    "lounge", "luck", "lung", "macro", "mail", "manage", "manual", "margin",
    "martial", "master", "meadow", "meat", "meet", "member", "mentor", "merit",
    "metal", "midday", "milk", "mingle", "mirror", "mobile", "modest", "monitor",
    "morning", "motion", "mouse", "muffin", "muscle", "myself", "nail", "nation",
    "navy", "nectar", "nerve", "never", "nickel", "noble", "noon", "notable",
    "noun", "nugget", "obey", "occupy", "offer", "omega", "only", "opera",
    "orange", "organ", "ostrich", "outdoor", "output", "overall", "pace", "palace",
    "panic", "parcel", "parrot", "pasta", "path", "pattern", "peak", "pebble",
    "pencil", "perfect", "permit", "phase", "picnic", "pilot", "pioneer", "piston",
    "pizza", "plaster", "pledge", "pocket", "polar", "pony", "poppy", "possum",
    "pottery", "praise", "prefer", "pretty", "primal", "prize", "produce", "promise",
    "proud", "pudding", "pumpkin", "pure", "puzzle", "quality", "query", "quiet",
    "quiver", "race", "raft", "rally", "rapid", "ratio", "reach", "reason",
    "receipt", "recover", "reef", "regard", "relax", "remain", "remove", "repair",
    "report", "reside", "restore", "retreat", "review", "rhubarb", "riddle", "right",
    "rise", "river", "robot", "role", "room", "rose", "round", "rudder",
    "runner", "rustic", "safety", "salmon", "sample", "sausage", "scan", "scenic",
    "school", "scope", "screen", "seagull", "second", "seed", "seller", "sense",
    "series", "settle", "shallow", "sharp", "sheet", "sherbet", "ship", "shop",
    "shower", "sibling", "sight", "silver", "sister", "skill", "sled", "slide",
    "slope", "smart", "snack", "snow", "socket", "soil", "song", "sort",
    "source", "speak", "spell", "spike", "split", "sport", "spring", "square",
    "stack", "stamp", "state", "steel", "stew", "stitch", "stop", "strain",
    "stream", "strike", "studio", "suburb", "suit", "sunrise", "supply", "surname",
    "swamp", "sweep", "swing", "syrup", "tackle", "talent", "tank", "teach",
    "tease", "tempo", "tenor", "terrain", "theme", "thigh", "third", "thrill",
    "thumb", "tide", "timber", "title", "tofu", "tomato", "tool", "torch",
    "tour", "track", "train", "trap", "tree", "tribe", "trip", "tropic",
    "true", "truth", "tuna", "turf", "tutor", "twig", "unable", "unfold",
    "unique", "unpack", "upbeat", "upland", "upward", "usher", "vacant", "valley",
    "vanish", "vase", "velvet", "verdict", "vest", "video", "vine", "violin",
    "visit", "vocal", "vowel", "wagon", "walk", "want", "wash", "wave",
    "weight", "whale", "whisk", "widen", "wind", "wipe", "wish", "wood",
    "world", "wreath", "xenon", "yawn", "yield", "young", "zenith", "zipper",
];

// ---------------------------------------------------------------------------
// Scratch buffers
// ---------------------------------------------------------------------------

/// A page-locked working buffer, wiped *before* its lock is released.
///
/// The ordering is the one [`crate::record::Secret`] documents and 0.4.10 got
/// wrong: zeroize first, unlock second. Letting the guard drop first would
/// leave a window, however brief, in which the plaintext is both present and
/// swappable. The buffer is allocated at its final length and only ever indexed
/// into, never pushed to, so it cannot reallocate and strand a copy.
struct Scratch {
    buf: Vec<u8>,
    lock: Option<memlock::Lock>,
}

impl Scratch {
    fn new(len: usize) -> Self {
        let buf = vec![0u8; len];
        let lock = memlock::Lock::new(&buf);
        Self { buf, lock }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.buf.zeroize();
        drop(self.lock.take());
    }
}

// ---------------------------------------------------------------------------
// Uniform selection
// ---------------------------------------------------------------------------

/// A uniformly distributed value in `0..n`.
///
/// Masks to the next power of two and redraws on overshoot. `next_u32() % n` is
/// what this replaces: for any `n` that is not a power of two it hands the low
/// residues one extra chance and skews the output toward the front of the
/// charset. Masking discards the skewed values instead of folding them.
///
/// Acceptance probability exceeds one half for every `n`, so the loop is
/// expected to run under twice; [`MAX_DRAWS`] converts an RNG malfunction into
/// an error rather than a hang.
fn uniform_below<R: RngCore>(rng: &mut R, n: u32) -> Result<u32> {
    if n == 0 {
        bail!("internal error: uniform_below called with an empty range");
    }
    if n == 1 {
        return Ok(0);
    }
    let bits = u32::BITS - (n - 1).leading_zeros();
    let mask = if bits >= u32::BITS {
        u32::MAX
    } else {
        (1u32 << bits) - 1
    };
    for _ in 0..MAX_DRAWS {
        let candidate = rng.next_u32() & mask;
        if candidate < n {
            return Ok(candidate);
        }
    }
    bail!("the system RNG produced {MAX_DRAWS} consecutive out-of-range draws")
}

// ---------------------------------------------------------------------------
// Specifications
// ---------------------------------------------------------------------------

/// What kind of password to mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordSpec {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Drop the glyphs listed in [`AMBIGUOUS`]. This shrinks the alphabet, and
    /// the reported entropy shrinks with it.
    pub exclude_ambiguous: bool,
}

impl Default for PasswordSpec {
    /// Twenty characters over all four classes, ambiguous glyphs kept.
    ///
    /// Exclusion is off by default because it costs real entropy and only pays
    /// for itself when a human has to transcribe the secret by eye.
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

/// What kind of passphrase to mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphraseSpec {
    pub words: usize,
    pub separator: char,
    /// Upper-cases the first letter of every word. Deterministic, and therefore
    /// worth exactly zero bits — see [`strength_of_passphrase`].
    pub capitalise: bool,
}

impl Default for PassphraseSpec {
    /// Eight words, which is 72 bits.
    ///
    /// Seven would be 63, and would land one bit inside
    /// [`StrengthLabel::Weak`]. The threshold is the honest one, so the default
    /// moves rather than the bucket.
    fn default() -> Self {
        Self {
            words: 8,
            separator: '-',
            capitalise: false,
        }
    }
}

impl PasswordSpec {
    fn enabled_classes(&self) -> usize {
        usize::from(self.lowercase)
            + usize::from(self.uppercase)
            + usize::from(self.digits)
            + usize::from(self.symbols)
    }

    /// Check the spec can produce anything, without producing it.
    pub fn validate(&self) -> Result<()> {
        Charset::build(self).map(|_| ())
    }
}

impl PassphraseSpec {
    /// Check the spec can produce anything, without producing it.
    pub fn validate(&self) -> Result<()> {
        if self.words == 0 {
            bail!("a passphrase needs at least one word");
        }
        if self.words > MAX_PASSPHRASE_WORDS {
            bail!("a passphrase may have at most {MAX_PASSPHRASE_WORDS} words");
        }
        if self.separator.is_control() {
            bail!("the separator must not be a control character");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Charset assembly
// ---------------------------------------------------------------------------

/// The resolved alphabet, plus the class each byte belongs to.
struct Charset {
    bytes: Vec<u8>,
    /// Class index per byte value, or [`Charset::NONE`] when outside the set.
    class_of: [u8; 256],
    /// Size of each enabled class after exclusion. Sums to `bytes.len()`.
    class_sizes: Vec<usize>,
}

impl Charset {
    const NONE: u8 = u8::MAX;

    fn build(spec: &PasswordSpec) -> Result<Self> {
        if spec.length == 0 {
            bail!("password length must be at least 1");
        }
        if spec.length > MAX_PASSWORD_LEN {
            bail!("password length must be at most {MAX_PASSWORD_LEN}");
        }
        if spec.enabled_classes() == 0 {
            bail!("at least one character class must be enabled");
        }

        let mut bytes = Vec::new();
        let mut class_of = [Self::NONE; 256];
        let mut class_sizes = Vec::new();

        let sources = [
            (spec.lowercase, LOWERCASE),
            (spec.uppercase, UPPERCASE),
            (spec.digits, DIGITS),
            (spec.symbols, SYMBOLS),
        ];
        for (enabled, source) in sources {
            if !enabled {
                continue;
            }
            let index = class_sizes.len();
            let mut size = 0usize;
            for &b in source.as_bytes() {
                if spec.exclude_ambiguous && AMBIGUOUS.as_bytes().contains(&b) {
                    continue;
                }
                class_of[b as usize] = index as u8;
                bytes.push(b);
                size += 1;
            }
            if size == 0 {
                bail!("excluding ambiguous characters emptied an enabled character class");
            }
            class_sizes.push(size);
        }

        if spec.length < class_sizes.len() {
            bail!(
                "length {} cannot hold all {} enabled character classes",
                spec.length,
                class_sizes.len()
            );
        }

        Ok(Self {
            bytes,
            class_of,
            class_sizes,
        })
    }

    /// Whether every enabled class is represented in `candidate`.
    fn all_classes_present(&self, candidate: &[u8]) -> bool {
        let wanted = (1u32 << self.class_sizes.len()) - 1;
        let mut seen = 0u32;
        for &b in candidate {
            let class = self.class_of[b as usize];
            if class != Self::NONE {
                seen |= 1 << class;
            }
            if seen == wanted {
                return true;
            }
        }
        seen == wanted
    }
}

// ---------------------------------------------------------------------------
// Strength
// ---------------------------------------------------------------------------

/// A coarse bucket over [`Strength::entropy_bits`].
///
/// The thresholds are a stated convention, not a prediction: turning bits into
/// a cracking time needs a guess rate and a hash cost, neither of which this
/// module can observe. Anything that claims otherwise is guessing on the
/// reader's behalf. [`Strength::basis`] is the field that carries the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrengthLabel {
    /// The specification generates nothing at all. Not a weak secret: no secret.
    Unusable,
    /// Under 32 bits.
    Trivial,
    /// 32 to 63 bits.
    Weak,
    /// 64 to 79 bits.
    Moderate,
    /// 80 to 127 bits.
    Strong,
    /// 128 bits or more.
    VeryStrong,
}

impl StrengthLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            StrengthLabel::Unusable => "unusable",
            StrengthLabel::Trivial => "trivial",
            StrengthLabel::Weak => "weak",
            StrengthLabel::Moderate => "moderate",
            StrengthLabel::Strong => "strong",
            StrengthLabel::VeryStrong => "very strong",
        }
    }

    fn for_bits(bits: f64) -> Self {
        if !bits.is_finite() || bits <= 0.0 {
            StrengthLabel::Unusable
        } else if bits < 32.0 {
            StrengthLabel::Trivial
        } else if bits < 64.0 {
            StrengthLabel::Weak
        } else if bits < 80.0 {
            StrengthLabel::Moderate
        } else if bits < 128.0 {
            StrengthLabel::Strong
        } else {
            StrengthLabel::VeryStrong
        }
    }
}

impl std::fmt::Display for StrengthLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a generator is worth, and what that figure assumes.
///
/// Only ever constructed from a specification. The invariant is
/// `entropy_bits == length * log2(charset_size) + class_constraint_bits`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Strength {
    /// Bits of entropy in a value drawn by this generator.
    pub entropy_bits: f64,
    /// Symbols the generator draws from — characters, or words for a passphrase.
    pub charset_size: usize,
    /// Draws the generator makes — characters, or words for a passphrase.
    pub length: usize,
    /// Always `<= 0.0`. What requiring every enabled class costs.
    ///
    /// Rejecting draws that miss a class makes the output uniform over a
    /// *smaller* set than `charset_size^length`, so it lowers entropy. Meters
    /// that impose the requirement and still quote the unconstrained figure are
    /// overstating, which is why this is a separate field rather than a silent
    /// adjustment. Zero when fewer than two classes are enabled.
    pub class_constraint_bits: f64,
    pub label: StrengthLabel,
    /// What the number assumes, in plain words, for display next to it.
    pub basis: String,
}

/// `log2` of the probability that a uniform draw contains every class.
///
/// Inclusion–exclusion over the class subsets, factored by `charset^length` so
/// the sum stays in `[0, 1]` and no big integers are needed. The caller must
/// have established `length >= class_sizes.len()`; when the constraint is
/// unsatisfiable this returns `NEG_INFINITY`, which callers map to
/// [`StrengthLabel::Unusable`] rather than to a number.
fn class_constraint_bits(charset_size: usize, class_sizes: &[usize], length: usize) -> f64 {
    let classes = class_sizes.len();
    if classes < 2 {
        return 0.0;
    }
    let total = charset_size as f64;
    let exponent = length as i32;
    let mut probability = 0.0f64;
    for subset in 0u32..(1u32 << classes) {
        let mut removed = 0usize;
        for (index, size) in class_sizes.iter().enumerate() {
            if subset >> index & 1 == 1 {
                removed += size;
            }
        }
        let term = ((charset_size - removed) as f64 / total).powi(exponent);
        if subset.count_ones() % 2 == 0 {
            probability += term;
        } else {
            probability -= term;
        }
    }
    if probability <= 0.0 {
        return f64::NEG_INFINITY;
    }
    probability.log2()
}

const PROVENANCE: &str = "generated values only, never a typed one";

/// What [`password`] would be worth for this spec.
///
/// Returns [`StrengthLabel::Unusable`] with an explanatory basis for a spec
/// that cannot generate anything, rather than a zero that reads like a
/// measurement.
pub fn strength_of_spec(spec: &PasswordSpec) -> Strength {
    let set = match Charset::build(spec) {
        Ok(set) => set,
        Err(e) => {
            return Strength {
                entropy_bits: 0.0,
                charset_size: 0,
                length: spec.length,
                class_constraint_bits: 0.0,
                label: StrengthLabel::Unusable,
                basis: format!("no value can be generated: {e}"),
            }
        }
    };

    let charset_size = set.bytes.len();
    let classes = set.class_sizes.len();
    let constraint = class_constraint_bits(charset_size, &set.class_sizes, spec.length);
    let unconstrained = spec.length as f64 * (charset_size as f64).log2();
    let entropy_bits = unconstrained + constraint;

    let basis = if !entropy_bits.is_finite() {
        format!(
            "no value can be generated: {} characters cannot cover {classes} classes",
            spec.length
        )
    } else if classes < 2 {
        format!(
            "uniform random over {charset_size} symbols, {} long; {PROVENANCE}",
            spec.length
        )
    } else {
        format!(
            "uniform random over {charset_size} symbols, {} long, redrawn until all \
             {classes} enabled classes appear (costs {:.3} bits); {PROVENANCE}",
            spec.length,
            -constraint
        )
    };

    Strength {
        entropy_bits: if entropy_bits.is_finite() {
            entropy_bits
        } else {
            0.0
        },
        charset_size,
        length: spec.length,
        class_constraint_bits: if constraint.is_finite() { constraint } else { 0.0 },
        label: StrengthLabel::for_bits(entropy_bits),
        basis,
    }
}

/// What [`passphrase`] would be worth for this spec.
///
/// The separator and the capitalisation are fixed, so both contribute nothing.
/// A meter that credits capitalisation is counting a constant.
pub fn strength_of_passphrase(spec: &PassphraseSpec) -> Strength {
    if let Err(e) = spec.validate() {
        return Strength {
            entropy_bits: 0.0,
            charset_size: WORDS.len(),
            length: spec.words,
            class_constraint_bits: 0.0,
            label: StrengthLabel::Unusable,
            basis: format!("no value can be generated: {e}"),
        };
    }
    let bits_per_word = (WORDS.len() as f64).log2();
    let entropy_bits = spec.words as f64 * bits_per_word;
    Strength {
        entropy_bits,
        charset_size: WORDS.len(),
        length: spec.words,
        class_constraint_bits: 0.0,
        label: StrengthLabel::for_bits(entropy_bits),
        basis: format!(
            "uniform random over a {}-word list, {} words, {bits_per_word} bits per word; \
             the separator and capitalisation are fixed and add nothing; {PROVENANCE}",
            WORDS.len(),
            spec.words
        ),
    }
}

/// What [`pin`] would be worth for this many digits.
pub fn strength_of_pin(digits: usize) -> Strength {
    if let Err(e) = check_pin_digits(digits) {
        return Strength {
            entropy_bits: 0.0,
            charset_size: DIGITS.len(),
            length: digits,
            class_constraint_bits: 0.0,
            label: StrengthLabel::Unusable,
            basis: format!("no value can be generated: {e}"),
        };
    }
    let entropy_bits = digits as f64 * (DIGITS.len() as f64).log2();
    Strength {
        entropy_bits,
        charset_size: DIGITS.len(),
        length: digits,
        class_constraint_bits: 0.0,
        label: StrengthLabel::for_bits(entropy_bits),
        basis: format!(
            "uniform random over {} digits, {digits} long; {PROVENANCE}",
            DIGITS.len()
        ),
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Mint a password matching `spec`.
///
/// Every enabled class is guaranteed to appear. That guarantee is met by
/// redrawing the whole value, never by placing one character per class and
/// shuffling: the shuffle approach is not uniform over the strings it can
/// produce — it over-represents strings holding exactly one character from a
/// class — which would make the figure in [`strength_of_spec`] wrong. Rejection
/// keeps the draw uniform over precisely the set that figure counts.
pub fn password(spec: &PasswordSpec) -> Result<Secret> {
    let set = Charset::build(spec)?;
    let mut rng = OsRng;
    let mut scratch = Scratch::new(spec.length);
    let range = set.bytes.len() as u32;

    for _ in 0..MAX_CONSTRAINT_ATTEMPTS {
        for slot in scratch.buf.iter_mut() {
            *slot = set.bytes[uniform_below(&mut rng, range)? as usize];
        }
        if set.all_classes_present(&scratch.buf) {
            return Ok(Secret::new(&scratch.buf));
        }
    }
    bail!(
        "could not draw a password containing every enabled class in \
         {MAX_CONSTRAINT_ATTEMPTS} attempts"
    )
}

/// Mint a passphrase matching `spec` from the embedded [`WORDS`] list.
pub fn passphrase(spec: &PassphraseSpec) -> Result<Secret> {
    spec.validate()?;
    let mut rng = OsRng;

    // The words are public; which ones were drawn is the secret, so the index
    // vector is wiped alongside the assembled phrase.
    let mut picks: Zeroizing<Vec<u16>> = Zeroizing::new(vec![0u16; spec.words]);
    for slot in picks.iter_mut() {
        *slot = uniform_below(&mut rng, WORDS.len() as u32)? as u16;
    }

    let mut separator_buf = [0u8; 4];
    let separator = spec.separator.encode_utf8(&mut separator_buf).as_bytes();
    let total: usize = picks
        .iter()
        .map(|&i| WORDS[i as usize].len())
        .sum::<usize>()
        + separator.len() * (spec.words - 1);

    let mut scratch = Scratch::new(total);
    let mut at = 0usize;
    for (position, &index) in picks.iter().enumerate() {
        if position > 0 {
            scratch.buf[at..at + separator.len()].copy_from_slice(separator);
            at += separator.len();
        }
        let word = WORDS[index as usize].as_bytes();
        scratch.buf[at..at + word.len()].copy_from_slice(word);
        if spec.capitalise {
            scratch.buf[at] = scratch.buf[at].to_ascii_uppercase();
        }
        at += word.len();
    }
    debug_assert_eq!(at, total);

    Ok(Secret::new(&scratch.buf))
}

fn check_pin_digits(digits: usize) -> Result<()> {
    if digits == 0 {
        bail!("a PIN needs at least one digit");
    }
    if digits > MAX_PIN_DIGITS {
        bail!("a PIN may have at most {MAX_PIN_DIGITS} digits");
    }
    Ok(())
}

/// Mint a numeric PIN.
///
/// Short PINs are permitted. This module reports what a generator is worth
/// rather than enforcing a policy, and [`strength_of_pin`] will say plainly
/// that four digits is 13 bits.
pub fn pin(digits: usize) -> Result<Secret> {
    check_pin_digits(digits)?;
    let mut rng = OsRng;
    let mut scratch = Scratch::new(digits);
    for slot in scratch.buf.iter_mut() {
        *slot = DIGITS.as_bytes()[uniform_below(&mut rng, DIGITS.len() as u32)? as usize];
    }
    Ok(Secret::new(&scratch.buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hands out a fixed sequence, so rejection behaviour can be observed
    /// directly instead of inferred from a histogram.
    struct ScriptedRng {
        values: Vec<u32>,
        at: usize,
    }

    impl ScriptedRng {
        fn new(values: Vec<u32>) -> Self {
            Self { values, at: 0 }
        }
    }

    impl RngCore for ScriptedRng {
        fn next_u32(&mut self) -> u32 {
            let value = self.values[self.at];
            self.at += 1;
            value
        }
        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32())
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                *byte = self.next_u32() as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn expose(secret: &Secret) -> String {
        secret.expose_str().expect("generated secrets are UTF-8")
    }

    // -- the wordlist itself -------------------------------------------------

    #[test]
    fn wordlist_is_sorted_deduplicated_and_a_power_of_two() {
        assert_eq!(WORDS.len(), 512, "9 bits per word depends on this");
        assert_eq!(
            (WORDS.len() as f64).log2(),
            9.0,
            "the list size must be an exact power of two"
        );
        for pair in WORDS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "wordlist must be strictly ascending, so it cannot contain a \
                 duplicate that would silently lower the true entropy: {:?}",
                pair
            );
        }
        for word in WORDS {
            assert!(
                (4..=7).contains(&word.len())
                    && word.bytes().all(|b| b.is_ascii_lowercase()),
                "unexpected wordlist entry: {word}"
            );
        }
    }

    // -- uniform selection ---------------------------------------------------

    #[test]
    fn out_of_range_draws_are_rejected_not_folded() {
        // n = 90 masks to 7 bits, so 90..=127 are out of range. A `% n`
        // implementation would return 90 % 90 == 0 for the first draw; a
        // masking one must discard all three and return the 5.
        let mut rng = ScriptedRng::new(vec![90, 127, 100, 5]);
        assert_eq!(uniform_below(&mut rng, 90).unwrap(), 5);
        assert_eq!(rng.at, 4, "all three out-of-range draws must be consumed");
    }

    #[test]
    fn only_the_low_masked_bits_are_used() {
        let mut rng = ScriptedRng::new(vec![0xFFFF_FF05]);
        assert_eq!(uniform_below(&mut rng, 90).unwrap(), 5);
    }

    #[test]
    fn a_power_of_two_range_never_rejects() {
        let mut rng = ScriptedRng::new(vec![511, 0, 256]);
        assert_eq!(uniform_below(&mut rng, 512).unwrap(), 511);
        assert_eq!(uniform_below(&mut rng, 512).unwrap(), 0);
        assert_eq!(uniform_below(&mut rng, 512).unwrap(), 256);
    }

    #[test]
    fn a_single_valued_range_consumes_no_randomness() {
        let mut rng = ScriptedRng::new(vec![]);
        assert_eq!(uniform_below(&mut rng, 1).unwrap(), 0);
    }

    #[test]
    fn an_rng_that_never_lands_in_range_is_an_error_not_a_hang() {
        let mut rng = ScriptedRng::new(vec![127; MAX_DRAWS as usize + 8]);
        assert!(uniform_below(&mut rng, 90).is_err());
    }

    #[test]
    fn an_empty_range_is_an_error_not_a_panic() {
        let mut rng = ScriptedRng::new(vec![0]);
        assert!(uniform_below(&mut rng, 0).is_err());
    }

    #[test]
    fn selection_covers_its_range_without_gross_skew() {
        // Catches a wholesale failure of the sampler. It cannot catch modulo
        // bias at u32 width — that skew is around one part in 10^9 — which is
        // exactly why `out_of_range_draws_are_rejected_not_folded` exists.
        let mut rng = OsRng;
        let mut counts = [0u32; 3];
        for _ in 0..60_000 {
            counts[uniform_below(&mut rng, 3).unwrap() as usize] += 1;
        }
        for count in counts {
            assert!(
                (19_000..=21_000).contains(&count),
                "bucket {count} is far from the expected 20000: {counts:?}"
            );
        }
    }

    // -- password shape ------------------------------------------------------

    #[test]
    fn requested_length_is_honoured() {
        for length in [4, 5, 7, 20, 64, MAX_PASSWORD_LEN] {
            let spec = PasswordSpec {
                length,
                ..Default::default()
            };
            let secret = password(&spec).unwrap();
            assert_eq!(secret.len(), length);
            assert_eq!(expose(&secret).chars().count(), length);
        }
        // Lengths below the class count need a spec they can actually satisfy.
        for length in [1usize, 2, 3] {
            let spec = PasswordSpec {
                length,
                uppercase: false,
                digits: false,
                symbols: false,
                ..Default::default()
            };
            assert_eq!(password(&spec).unwrap().len(), length);
        }
    }

    #[test]
    fn every_enabled_class_appears() {
        let specs = [
            PasswordSpec::default(),
            PasswordSpec {
                length: 4,
                ..Default::default()
            },
            PasswordSpec {
                length: 8,
                symbols: false,
                ..Default::default()
            },
            PasswordSpec {
                length: 6,
                exclude_ambiguous: true,
                ..Default::default()
            },
        ];
        for spec in &specs {
            for _ in 0..64 {
                let value = expose(&password(spec).unwrap());
                assert_eq!(
                    spec.lowercase,
                    value.chars().any(|c| LOWERCASE.contains(c)),
                    "lowercase presence wrong for {spec:?}"
                );
                assert_eq!(
                    spec.uppercase,
                    value.chars().any(|c| UPPERCASE.contains(c)),
                    "uppercase presence wrong for {spec:?}"
                );
                assert_eq!(
                    spec.digits,
                    value.chars().any(|c| DIGITS.contains(c)),
                    "digit presence wrong for {spec:?}"
                );
                assert_eq!(
                    spec.symbols,
                    value.chars().any(|c| SYMBOLS.contains(c)),
                    "symbol presence wrong for {spec:?}"
                );
            }
        }
    }

    #[test]
    fn disabled_classes_never_appear() {
        let spec = PasswordSpec {
            length: 32,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        for _ in 0..32 {
            let value = expose(&password(&spec).unwrap());
            assert!(value.chars().all(|c| c.is_ascii_digit()), "{value:?}");
        }
    }

    #[test]
    fn ambiguous_characters_are_excluded_when_asked() {
        let spec = PasswordSpec {
            length: 64,
            exclude_ambiguous: true,
            ..Default::default()
        };
        for _ in 0..64 {
            let value = expose(&password(&spec).unwrap());
            for glyph in AMBIGUOUS.chars() {
                assert!(
                    !value.contains(glyph),
                    "excluded glyph {glyph:?} survived into a generated password"
                );
            }
        }
        assert_eq!(
            strength_of_spec(&spec).charset_size,
            90 - AMBIGUOUS.len(),
            "exclusion must shrink the reported alphabet too"
        );
    }

    #[test]
    fn ambiguous_characters_do_appear_when_not_excluded() {
        // Guards against the exclusion being unconditional, which would make
        // the previous test pass for the wrong reason.
        let spec = PasswordSpec {
            length: 256,
            ..Default::default()
        };
        let value = expose(&password(&spec).unwrap());
        assert!(AMBIGUOUS.chars().any(|glyph| value.contains(glyph)));
    }

    #[test]
    fn generated_values_differ_across_calls() {
        let spec = PasswordSpec::default();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            assert!(
                seen.insert(expose(&password(&spec).unwrap())),
                "two calls produced the same password"
            );
        }
        let phrase_spec = PassphraseSpec::default();
        let mut phrases = std::collections::HashSet::new();
        for _ in 0..64 {
            assert!(phrases.insert(expose(&passphrase(&phrase_spec).unwrap())));
        }
    }

    // -- entropy arithmetic --------------------------------------------------

    #[test]
    fn entropy_matches_log2_charset_pow_length_for_one_class() {
        // With a single class the constraint is vacuous, so the figure is
        // exactly log2(charset^length).
        for length in [1usize, 5, 20, 64] {
            let spec = PasswordSpec {
                length,
                lowercase: true,
                uppercase: false,
                digits: false,
                symbols: false,
                exclude_ambiguous: false,
            };
            let strength = strength_of_spec(&spec);
            assert_eq!(strength.charset_size, 26);
            assert_eq!(strength.class_constraint_bits, 0.0);
            let expected = (26f64.powi(length as i32)).log2();
            assert!(
                (strength.entropy_bits - expected).abs() < 1e-9,
                "{} vs {expected}",
                strength.entropy_bits
            );
        }
    }

    #[test]
    fn strength_invariant_holds() {
        for spec in [
            PasswordSpec::default(),
            PasswordSpec {
                length: 12,
                exclude_ambiguous: true,
                ..Default::default()
            },
            PasswordSpec {
                length: 5,
                symbols: false,
                ..Default::default()
            },
        ] {
            let s = strength_of_spec(&spec);
            let rebuilt =
                s.length as f64 * (s.charset_size as f64).log2() + s.class_constraint_bits;
            assert!((s.entropy_bits - rebuilt).abs() < 1e-9);
        }
    }

    #[test]
    fn requiring_every_class_lowers_the_reported_entropy() {
        let spec = PasswordSpec::default();
        let strength = strength_of_spec(&spec);
        let unconstrained = spec.length as f64 * (strength.charset_size as f64).log2();

        assert!(
            strength.class_constraint_bits < 0.0,
            "requiring all four classes must cost something"
        );
        assert!(
            strength.entropy_bits < unconstrained,
            "the constrained generator cannot be worth more than the free one"
        );
        assert!(
            strength.basis.contains("costs"),
            "the cost must be visible in the basis: {}",
            strength.basis
        );
    }

    #[test]
    fn class_constraint_matches_an_exhaustive_count() {
        // Small enough to enumerate: lowercase + digits over lengths 2 and 3.
        // The reported entropy must be log2 of the number of strings that
        // actually satisfy the class requirement, counted by brute force.
        for length in [2usize, 3] {
            let spec = PasswordSpec {
                length,
                lowercase: true,
                uppercase: false,
                digits: true,
                symbols: false,
                exclude_ambiguous: false,
            };
            let set = Charset::build(&spec).unwrap();
            assert_eq!(set.bytes.len(), 36);

            let mut valid = 0u64;
            let total = 36usize.pow(length as u32);
            let mut candidate = vec![0u8; length];
            for n in 0..total {
                let mut rest = n;
                for slot in candidate.iter_mut() {
                    *slot = set.bytes[rest % 36];
                    rest /= 36;
                }
                if set.all_classes_present(&candidate) {
                    valid += 1;
                }
            }

            let strength = strength_of_spec(&spec);
            let counted_bits = (valid as f64).log2();
            assert!(
                (strength.entropy_bits - counted_bits).abs() < 1e-9,
                "length {length}: reported {} bits, exhaustive count says {counted_bits} \
                 ({valid} valid strings)",
                strength.entropy_bits
            );
        }
    }

    #[test]
    fn passphrase_entropy_is_nine_bits_per_word() {
        for words in [1usize, 4, 7, MAX_PASSPHRASE_WORDS] {
            let spec = PassphraseSpec {
                words,
                ..Default::default()
            };
            let strength = strength_of_passphrase(&spec);
            assert_eq!(strength.charset_size, 512);
            assert_eq!(strength.length, words);
            assert_eq!(strength.entropy_bits, words as f64 * 9.0);
        }
    }

    #[test]
    fn capitalisation_and_separator_are_worth_nothing() {
        let plain = PassphraseSpec::default();
        let dressed = PassphraseSpec {
            capitalise: true,
            separator: '.',
            ..PassphraseSpec::default()
        };
        assert_eq!(
            strength_of_passphrase(&plain).entropy_bits,
            strength_of_passphrase(&dressed).entropy_bits
        );
        assert!(strength_of_passphrase(&dressed)
            .basis
            .contains("add nothing"));
    }

    #[test]
    fn pin_strength_is_log2_ten_per_digit() {
        let strength = strength_of_pin(4);
        assert!((strength.entropy_bits - 4.0 * 10f64.log2()).abs() < 1e-9);
        assert_eq!(strength.label, StrengthLabel::Trivial);
    }

    #[test]
    fn labels_bucket_as_documented() {
        assert_eq!(StrengthLabel::for_bits(0.0), StrengthLabel::Unusable);
        assert_eq!(StrengthLabel::for_bits(f64::NAN), StrengthLabel::Unusable);
        assert_eq!(StrengthLabel::for_bits(31.9), StrengthLabel::Trivial);
        assert_eq!(StrengthLabel::for_bits(32.0), StrengthLabel::Weak);
        assert_eq!(StrengthLabel::for_bits(64.0), StrengthLabel::Moderate);
        assert_eq!(StrengthLabel::for_bits(80.0), StrengthLabel::Strong);
        assert_eq!(StrengthLabel::for_bits(128.0), StrengthLabel::VeryStrong);
        assert_eq!(StrengthLabel::VeryStrong.to_string(), "very strong");
        assert_eq!(StrengthLabel::Unusable.as_str(), "unusable");
    }

    #[test]
    fn the_default_spec_is_worth_having() {
        let strength = strength_of_spec(&PasswordSpec::default());
        assert_eq!(strength.charset_size, 90);
        assert_eq!(strength.length, 20);
        assert_eq!(strength.label, StrengthLabel::VeryStrong);
        assert!(strength.basis.contains("uniform random"));
        assert!(strength.basis.contains("never a typed one"));

        let phrase = strength_of_passphrase(&PassphraseSpec::default());
        assert_eq!(phrase.entropy_bits, 72.0);
        assert_eq!(phrase.label, StrengthLabel::Moderate);
        assert_eq!(
            strength_of_passphrase(&PassphraseSpec {
                words: 7,
                ..Default::default()
            })
            .label,
            StrengthLabel::Weak,
            "63 bits is under the documented 64-bit threshold and must say so"
        );
    }

    // -- absurd specifications ----------------------------------------------

    #[test]
    fn absurd_password_specs_are_errors_not_panics() {
        let cases = [
            PasswordSpec {
                length: 0,
                ..Default::default()
            },
            PasswordSpec {
                length: MAX_PASSWORD_LEN + 1,
                ..Default::default()
            },
            PasswordSpec {
                length: 8,
                lowercase: false,
                uppercase: false,
                digits: false,
                symbols: false,
                exclude_ambiguous: false,
            },
            // Three characters cannot hold four classes.
            PasswordSpec {
                length: 3,
                ..Default::default()
            },
        ];
        for spec in &cases {
            assert!(password(spec).is_err(), "expected an error for {spec:?}");
            assert!(spec.validate().is_err());
            let strength = strength_of_spec(spec);
            assert_eq!(
                strength.label,
                StrengthLabel::Unusable,
                "an impossible spec must not report a number: {strength:?}"
            );
            assert!(strength.basis.starts_with("no value can be generated"));
        }
    }

    #[test]
    fn absurd_passphrase_and_pin_specs_are_errors_not_panics() {
        for words in [0, MAX_PASSPHRASE_WORDS + 1] {
            let spec = PassphraseSpec {
                words,
                ..Default::default()
            };
            assert!(passphrase(&spec).is_err());
            assert_eq!(
                strength_of_passphrase(&spec).label,
                StrengthLabel::Unusable
            );
        }
        let control = PassphraseSpec {
            separator: '\n',
            ..Default::default()
        };
        assert!(passphrase(&control).is_err());

        for digits in [0, MAX_PIN_DIGITS + 1] {
            assert!(pin(digits).is_err());
            assert_eq!(strength_of_pin(digits).label, StrengthLabel::Unusable);
        }
    }

    #[test]
    fn a_spec_whose_exclusion_would_empty_a_class_is_rejected() {
        // Every ambiguous glyph happens to live in a class with survivors, so
        // this asserts the guard exists rather than that it fires today.
        let spec = PasswordSpec {
            length: 8,
            exclude_ambiguous: true,
            ..Default::default()
        };
        let set = Charset::build(&spec).unwrap();
        assert!(set.class_sizes.iter().all(|&size| size > 0));
        assert_eq!(set.class_sizes.iter().sum::<usize>(), set.bytes.len());
    }

    // -- passphrase and pin shape -------------------------------------------

    #[test]
    fn passphrase_uses_only_listed_words_in_the_requested_shape() {
        let spec = PassphraseSpec {
            words: 5,
            separator: '-',
            capitalise: false,
        };
        for _ in 0..32 {
            let value = expose(&passphrase(&spec).unwrap());
            let parts: Vec<&str> = value.split('-').collect();
            assert_eq!(parts.len(), 5);
            for part in parts {
                assert!(WORDS.contains(&part), "{part:?} is not in the wordlist");
            }
        }
    }

    #[test]
    fn capitalise_upper_cases_each_word() {
        let spec = PassphraseSpec {
            words: 4,
            separator: '.',
            capitalise: true,
        };
        let value = expose(&passphrase(&spec).unwrap());
        let parts: Vec<&str> = value.split('.').collect();
        assert_eq!(parts.len(), 4);
        for part in parts {
            let first = part.chars().next().unwrap();
            assert!(first.is_ascii_uppercase(), "{part:?}");
            assert!(WORDS.contains(&part.to_ascii_lowercase().as_str()));
        }
    }

    #[test]
    fn a_single_word_passphrase_has_no_separator() {
        let spec = PassphraseSpec {
            words: 1,
            ..Default::default()
        };
        let value = expose(&passphrase(&spec).unwrap());
        assert!(!value.contains('-'));
        assert!(WORDS.contains(&value.as_str()));
    }

    #[test]
    fn multibyte_separators_are_handled() {
        let spec = PassphraseSpec {
            words: 3,
            separator: '·',
            capitalise: false,
        };
        let value = expose(&passphrase(&spec).unwrap());
        assert_eq!(value.split('·').count(), 3);
    }

    #[test]
    fn pin_is_all_digits_of_the_requested_length() {
        for digits in [1usize, 4, 6, MAX_PIN_DIGITS] {
            let secret = pin(digits).unwrap();
            assert_eq!(secret.len(), digits);
            let value = expose(&secret);
            assert!(value.chars().all(|c| c.is_ascii_digit()), "{value:?}");
        }
    }

    // -- the house rule ------------------------------------------------------

    #[test]
    fn debug_never_prints_a_generated_secret() {
        let cases = [
            password(&PasswordSpec::default()).unwrap(),
            passphrase(&PassphraseSpec::default()).unwrap(),
            pin(8).unwrap(),
        ];
        for secret in &cases {
            let value = expose(secret);
            let shown = format!("{secret:?}");
            assert!(!shown.contains(&value), "Debug leaked a secret: {shown}");
            assert!(shown.contains("redacted"));
        }
    }

    #[test]
    fn strength_carries_no_secret_material() {
        // Strength is derived from a spec and never sees a value, so this is a
        // regression guard on that separation rather than on a formatting bug.
        let spec = PasswordSpec::default();
        let secret = password(&spec).unwrap();
        let value = expose(&secret);
        let rendered = format!("{:?}", strength_of_spec(&spec));
        assert!(!rendered.contains(&value));
    }
}
