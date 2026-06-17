#![no_main]

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};
use serde_saphyr::{CommentPosition, SerializerOptions};

const MAX_DEPTH: u32 = 4;
const MAX_BREADTH: usize = 4;

/// NaN-aware float wrapper.
///
/// The full `f64::arbitrary` range is fed in (subnormals, infinities, very large
/// and very small magnitudes, NaN, `-0.0`), so the float-formatting path is fully
/// exercised. Equality treats `NaN == NaN`, and `0.0 == -0.0` falls out of the
/// regular `==` so neither is a false positive on round-trip.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
struct F64(f64);

impl PartialEq for F64 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 || (self.0.is_nan() && other.0.is_nan())
    }
}

/// A small, recursive data model covering the YAML node kinds and every scalar
/// flavour the serializer has a dedicated path for.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
enum Node {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    I128(i128),
    U128(u128),
    Float(F64),
    Char(char),
    Str(String),
    Opt(Option<Box<Node>>),
    EnumTuple(Box<Node>, Box<Node>),
    EnumStruct { field: Box<Node> },
    Seq(Vec<Node>),
    Map(BTreeMap<String, Node>),
}

/// Serializer options derived from the fuzz input. Held as plain `Debug`-able
/// fields (the real `SerializerOptions` is neither `Debug` nor easily literal)
/// so a failing case prints exactly which configuration triggered it.
#[derive(Debug)]
struct Opts {
    indent_step: usize,
    compact_list_indent: bool,
    min_fold_chars: usize,
    folded_wrap_chars: usize,
    tagged_enums: bool,
    empty_as_braces: bool,
    prefer_block_scalars: bool,
    quote_all: bool,
    yaml_12: bool,
    comment_above: bool,
}

impl Opts {
    fn to_options(&self) -> SerializerOptions {
        serde_saphyr::ser_options! {
            indent_step: self.indent_step,
            compact_list_indent: self.compact_list_indent,
            min_fold_chars: self.min_fold_chars,
            folded_wrap_chars: self.folded_wrap_chars,
            tagged_enums: self.tagged_enums,
            empty_as_braces: self.empty_as_braces,
            prefer_block_scalars: self.prefer_block_scalars,
            quote_all: self.quote_all,
            yaml_12: self.yaml_12,
            comment_position: if self.comment_above {
                CommentPosition::Above
            } else {
                CommentPosition::Inline
            },
        }
    }
}

impl<'a> Arbitrary<'a> for Opts {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Opts {
            // indent_step must be in 1..=65535; small values are where the
            // interesting layout edge cases live.
            indent_step: u.int_in_range(1..=10)?,
            compact_list_indent: bool::arbitrary(u)?,
            min_fold_chars: u.int_in_range(0..=64)?,
            folded_wrap_chars: u.int_in_range(1..=120)?,
            tagged_enums: bool::arbitrary(u)?,
            empty_as_braces: bool::arbitrary(u)?,
            prefer_block_scalars: bool::arbitrary(u)?,
            quote_all: bool::arbitrary(u)?,
            yaml_12: bool::arbitrary(u)?,
            comment_above: bool::arbitrary(u)?,
        })
    }
}

/// Strings that sit on the serializer's auto-quoting / block-style decision
/// boundaries: tokens that look like other YAML types, leading indicators,
/// flow punctuation, anchors/aliases/tags, comments, and a multi-line value
/// (which forces a block scalar). These are far more likely to expose quoting
/// bugs than purely random bytes.
const ADVERSARIAL: &[&str] = &[
    "",
    "null",
    "Null",
    "NULL",
    "~",
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
    "y",
    "n",
    "0",
    "00",
    "-5",
    "+1",
    "1_000",
    "0x1F",
    "0o17",
    "1.5",
    ".inf",
    "-.inf",
    ".nan",
    "1e10",
    "2001-12-15",
    "a: b",
    "a:b",
    "- item",
    "? key",
    "#comment",
    "key#notcomment",
    "@anchor",
    "&anchor",
    "*alias",
    "!tag",
    "!!str",
    "|literal",
    ">folded",
    "%directive",
    "[flow]",
    "{flow}",
    "'quoted'",
    "\"quoted\"",
    "a,b",
    "back\\slash",
    "uni\u{1F600}code",
    "\u{FEFF}bom",
    "line1\nline2\nline3",
    "trailing tabs and spaces in\tthe middle",
];

/// YAML-significant single characters (no control/whitespace chars, which would
/// hit the documented "trailing whitespace is not preserved" limitation).
const ADVERSARIAL_CHARS: &[char] = &[
    ':', '#', '-', '?', '&', '*', '!', '|', '>', '%', '@', ',', '[', ']', '{', '}', '"', '\'',
    '\\', 'a', '0', 'é', '😀',
];

/// Generate a string value/key. Mixes curated adversarial tokens, occasional
/// overly-long values (to trigger `? key` and folding paths), and random data.
///
/// NOTE: trailing/leading whitespace is trimmed because the serializer
/// intentionally does not preserve it (see `is_auto_block_scalar_readable` and
/// the chomping rules for block scalars), so it is a documented non-round-trip,
/// not a bug.
fn gen_string(u: &mut Unstructured) -> arbitrary::Result<String> {
    let s = if u.ratio(1, 3)? {
        (*u.choose(ADVERSARIAL)?).to_string()
    } else if u.ratio(1, 8)? {
        let raw = String::arbitrary(u)?;
        let seed = raw.trim();
        let seed = if seed.is_empty() { "k" } else { seed };
        seed.repeat(1024 / seed.len() + 2)
    } else {
        String::arbitrary(u)?
    };
    Ok(s.trim().to_string())
}

fn gen_node(u: &mut Unstructured, depth: u32) -> arbitrary::Result<Node> {
    // At depth 0, only scalar variants (indices 0..=8) are allowed.
    let max_variant: u32 = if depth == 0 { 8 } else { 13 };
    Ok(match u.int_in_range(0..=max_variant)? {
        0 => Node::Null,
        1 => Node::Bool(bool::arbitrary(u)?),
        2 => Node::Int(i64::arbitrary(u)?),
        3 => Node::UInt(u64::arbitrary(u)?),
        4 => Node::I128(i128::arbitrary(u)?),
        5 => Node::U128(u128::arbitrary(u)?),
        6 => Node::Float(F64(f64::arbitrary(u)?)),
        7 => Node::Char(*u.choose(ADVERSARIAL_CHARS)?),
        8 => Node::Str(gen_string(u)?),
        9 => {
            if bool::arbitrary(u)? {
                Node::Opt(Some(Box::new(gen_node(u, depth - 1)?)))
            } else {
                Node::Opt(None)
            }
        }
        10 => Node::EnumTuple(
            Box::new(gen_node(u, depth - 1)?),
            Box::new(gen_node(u, depth - 1)?),
        ),
        11 => Node::EnumStruct {
            field: Box::new(gen_node(u, depth - 1)?),
        },
        12 => {
            let n = u.int_in_range(0..=MAX_BREADTH)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(gen_node(u, depth - 1)?);
            }
            Node::Seq(v)
        }
        _ => {
            let n = u.int_in_range(0..=MAX_BREADTH)?;
            let mut m = BTreeMap::new();
            for _ in 0..n {
                let k = gen_string(u)?;
                let val = gen_node(u, depth - 1)?;
                m.insert(k, val);
            }
            Node::Map(m)
        }
    })
}

impl<'a> Arbitrary<'a> for Node {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        gen_node(u, MAX_DEPTH)
    }
}

/// The combined fuzz input: a value plus the serializer configuration to emit it
/// with. Round-trip equality and idempotence are invariants that must hold for
/// *every* valid option combination, so we fuzz the options alongside the value.
#[derive(Debug)]
struct FuzzInput {
    opts: Opts,
    node: Node,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(FuzzInput {
            opts: Opts::arbitrary(u)?,
            node: Node::arbitrary(u)?,
        })
    }
}

fuzz_target!(|input: FuzzInput| {
    let FuzzInput { opts, node } = input;
    let options = opts.to_options();

    // serialization is panic-free and from valid input, so may never return an `Err`
    let text = serde_saphyr::to_string_with_options(&node, options).unwrap();

    // anything we emit must be parseable YAML for this model.
    let back: Node = match serde_saphyr::from_str(&text) {
        Ok(back) => back,
        Err(e) => {
            panic!(
                "serializer emitted YAML that fails to parse back:\n---options---\n{opts:#?}\n---error---\n{e}\n--- yaml ---\n{text}\n---debug---\n{node:#?}"
            )
        }
    };

    // equality
    assert_eq!(
        node, back,
        "round-trip changed the value\n---options---\n{opts:#?}\n--- yaml ---\n{text}\n--- original ---\n{node:#?}\n--- decoded ---\n{back:#?}"
    );

    // idempotence
    let text2 = serde_saphyr::to_string_with_options(&back, options).unwrap();
    assert_eq!(
        text, text2,
        "serialization is not idempotent\n---options---\n{opts:#?}\n--- first ---\n{text}\n--- second ---\n{text2}\n--- value ---\n{node:#?}"
    );
});
