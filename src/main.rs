#![feature(test)]
extern crate test;
use test::Bencher;
extern crate lazy_static;
extern crate regex;

use lazy_static::lazy_static;
use regex::Regex;

use hyperscan::chimera::prelude::*;

const SINGLE_QUAD: &str = r#"_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/webledger#ContinuityMergeEvent> ."#;
const FIFTEEN_QUADS: &str = r#"_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/webledger#ContinuityMergeEvent> .
_:b0 <https://w3id.org/security#proof> _:b1 .
_:b0 <https://w3id.org/webledger#parentHash> "zQmPkZrQs9dyezAQkVniqkMjm5nP3cdWFBzNsnnFLrsNf9u" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmYDcw6hXTZHCYaPyuGLCo8jcNREidQs4ikwKdVyS5uwKA" .
_:b0 <https://w3id.org/webledger#parentHash> "zQma45eMXmzKBXYwLdU7FvAEW3ekMy4fJjqEQVhYQFgwYAP" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmb6eicGxT6FAAZdxEzam2JpPu8ajiMJYhzPnhgHJJKh8f" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmb6eicGxT6FAAZdxEzam2JpPu8ajiMJYhzPnhgHJJKh8g" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5F7" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmdxvSCwPjTvx3SAN2XHZ4uQpHKpbnHmns9BF8uZASW6Lx" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmePs3zy2fLPEsBXqGn2LPWSGYbzPy7CZTTz1f2ng3ysph" .
_:b0 <https://w3id.org/webledger#treeHash> "zQmPkZrQs9dyezAQkVniqkMjm5nP3cdWFBzNsnnFLrsNf9u" .
_:b2 <http://purl.org/dc/terms/created> "2018-12-21T23:40:20Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:b1 .
_:b2 <http://purl.org/dc/terms/creator> <https://bedrock.localhost:18443/consensus/continuity2017/voters/z6MkkabTusFkLnquxwHwCm28v59UX3P9Pn5scvc7fCaNvWUL> _:b1 .
_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2018> _:b1 .
_:b2 <https://w3id.org/security#jws> "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..JJ5c7mF7ru9XhPtrNqj1s6J74yqOC0HcNyK_Wa0OcfDaiODZFIJ2dXIrc_qqqvTWynIqJid6yXkKsGAzyi_HDQ" _:b1 .
"#;
const THIRTY_QUADS: &str = r#"_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/webledger#ContinuityMergeEvent> .
_:b0 <https://w3id.org/security#proof> _:b1 .
_:b0 <https://w3id.org/webledger#parentHash> "zQmPkZrQs9dyezAQkVniqkMjm5nP3cdWFBzNsnnFLrsNf9u" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmYDcw6hXTZHCYaPyuGLCo8jcNREidQs4ikwKdVyS5uwKA" .
_:b0 <https://w3id.org/webledger#parentHash> "zQma45eMXmzKBXYwLdU7FvAEW3ekMy4fJjqEQVhYQFgwYAP" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmb6eicGxT6FAAZdxEzam2JpPu8ajiMJYhzPnhgHJJKh8f" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fa" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fb" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fc" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fd" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fe" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Ff" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fg" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fh" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fi" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fj" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fk" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fl" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fm" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fn" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fo" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fp" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5Fq" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmdxvSCwPjTvx3SAN2XHZ4uQpHKpbnHmns9BF8uZASW6Lx" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmePs3zy2fLPEsBXqGn2LPWSGYbzPy7CZTTz1f2ng3ysph" .
_:b0 <https://w3id.org/webledger#treeHash> "zQmPkZrQs9dyezAQkVniqkMjm5nP3cdWFBzNsnnFLrsNf9u" .
_:b2 <http://purl.org/dc/terms/created> "2018-12-21T23:40:20Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:b1 .
_:b2 <http://purl.org/dc/terms/creator> <https://bedrock.localhost:18443/consensus/continuity2017/voters/z6MkkabTusFkLnquxwHwCm28v59UX3P9Pn5scvc7fCaNvWUL> _:b1 .
_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2018> _:b1 .
_:b2 <https://w3id.org/security#jws> "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..JJ5c7mF7ru9XhPtrNqj1s6J74yqOC0HcNyK_Wa0OcfDaiODZFIJ2dXIrc_qqqvTWynIqJid6yXkKsGAzyi_HDQ" _:b1 .
"#;

const VERES_ONE_DID: &str = r#"_:b0 <http://purl.org/dc/terms/creator> <https://ashburn.capybara.veres.one/consensus/continuity2017/voters/z6MkgTBtCodgNvf1SaQLRbCppkVMo7BggAP4NohtPY8ZNqic> .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/webledger#CreateWebLedgerRecord> .
_:b0 <https://w3id.org/security#proof> _:b1 .
_:b0 <https://w3id.org/security#proof> _:b3 .
_:b0 <https://w3id.org/webledger#record> "{\"@context\":[\"https://w3id.org/did/v0.11\",\"https://w3id.org/veres-one/v1\"],\"assertionMethod\":[{\"controller\":\"did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d\",\"id\":\"did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d#z6MkqVQKNUG994U8mK6p7CX6PMtijsgDuhQBUEXgfAPCqQEP\",\"publicKeyBase58\":\"C39GnE1hoWyfepG7RdZFYGLivJQNVp9pnDckptRBvBT1\",\"type\":\"Ed25519VerificationKey2018\"}],\"authentication\":[{\"controller\":\"did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d\",\"id\":\"did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d#z6MkjXWUNtoT9e1BDSt5zLmMuY7k9u99euxCQiduXCTwrY2u\",\"publicKeyBase58\":\"65FRneZ1p6Wi6x3PJmoX4SZkLKsJF2hqihiygvVvwKFX\",\"type\":\"Ed25519VerificationKey2018\"}],\"capabilityDelegation\":[{\"controller\":\"did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d\",\"id\":\"did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d#z6MknXoqGqfAG7vjBTPqNZjf1HWcMD2c5csTCkdkY62S8BRy\",\"publicKeyBase58\":\"95YngbQivaSG4xZ8gzmpABxcXdkkfjd6Wjiphp4RCxeb\",\"type\":\"Ed25519VerificationKey2018\"}],\"capabilityInvocation\":[{\"controller\":\"did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d\",\"id\":\"did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d#z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d\",\"publicKeyBase58\":\"3bKogxzDN4y6wv8rVncv23YEB3YW6MCWZUCVEAoGufMF\",\"type\":\"Ed25519VerificationKey2018\"}],\"id\":\"did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d\"}"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> .
_:b2 <http://purl.org/dc/terms/created> "2021-01-09T20:50:08Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:b1 .
_:b2 <http://purl.org/dc/terms/creator> <did:v1:test:nym:z279yHL6HsxRzCPU78DAWgZVieb8xPK1mJKJBbP8T2CezuFY#z279yHL6HsxRzCPU78DAWgZVieb8xPK1mJKJBbP8T2CezuFY> _:b1 .
_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2018> _:b1 .
_:b2 <https://w3id.org/security#capability> <did:v1:uuid:c37e914a-1e2a-4d59-9668-ee93458fd19a> _:b1 .
_:b2 <https://w3id.org/security#capabilityAction> "write" _:b1 .
_:b2 <https://w3id.org/security#jws> "MOCKPROOF" _:b1 .
_:b2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#capabilityInvocationMethod> _:b1 .
_:b4 <http://purl.org/dc/terms/created> "2021-01-09T20:50:08Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:b3 .
_:b4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2018> _:b3 .
_:b4 <https://w3id.org/security#capability> <did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d> _:b3 .
_:b4 <https://w3id.org/security#capabilityAction> "create" _:b3 .
_:b4 <https://w3id.org/security#jws> "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..u_T7y7P_woiPmpxfnY0rDdA_o25A9m9BOUfXu4zc1PqfIs92Po8sJn_D2xSPI2Ijuz22T6YibLtud1NgvFO1BQ" _:b3 .
_:b4 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#capabilityInvocationMethod> _:b3 .
_:b4 <https://w3id.org/security#verificationMethod> <did:v1:test:nym:z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d#z6Mkh3arHDEehcTa4QyZBMaks96DzcpMWESsFV7R4SmHpt8d> _:b3 .
"#;

// define partial regexes
const IRI: &str = "(?:<([^:]+:[^>]*)>)";
const PLAIN: &str = "\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"";
const LANGUAGE: &str = "(?:@([a-zA-Z]+(?:-[a-zA-Z0-9]+)*))";
const WS: &str = "[ \\t]+";
const WSO: &str = "[ \\t]*";

// XSD constants
// const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

// RDF constants
// const RDF_LANGSTRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";

lazy_static! {
  static ref PN_CHARS_BASE: String = format!(
    "{}{}{}{}{}{}{}{}{}{}{}{}{}",
    "A-Z",
    "a-z",
    "\u{00C0}-\u{00D6}",
    "\u{00D8}-\u{00F6}",
    "\u{00F8}-\u{02FF}",
    "\u{0370}-\u{037D}",
    "\u{037F}-\u{1FFF}",
    "\u{200C}-\u{200D}",
    "\u{2070}-\u{218F}",
    "\u{2C00}-\u{2FEF}",
    "\u{3001}-\u{D7FF}",
    "\u{F900}-\u{FDCF}",
    "\u{FDF0}-\u{FFFD}"
    // TODO:
    // "\u{1000}0-\u{EFFF}F"
  );
  static ref PN_CHARS_U: String = format!(
    "{}{}",
    PN_CHARS_BASE.as_str(),
    "_"
  );
  static ref PN_CHARS: String = format!(
    "{}{}{}{}{}{}",
    PN_CHARS_U.as_str(),
    "0-9",
    "-",
    "\u{00B7}",
    "\u{0300}-\u{036F}",
    "\u{203F}-\u{2040}"
  );
  // define partial regexes
  static ref BLANK_NODE_LABEL: String = format!(
    "{}{}{}{}{}{}{}{}{}{}",
    "(_:",
      "(?:[", PN_CHARS_U.as_str(), "0-9])",
      "(?:(?:[" , PN_CHARS.as_str() , ".])*(?:[" , PN_CHARS.as_str() , "]))?",
    ")"
  );
  static ref BNODE: String = BLANK_NODE_LABEL.clone();
  static ref DATATYPE: String = format!("{}{}{}", "(?:\\^\\^", IRI, ")");
  static ref LITERAL: String = format!("(?:{}(?:{}|{})?)", PLAIN, DATATYPE.as_str(), LANGUAGE);

  // define quad part regexes
  static ref SUBJECT: String = format!("(?:{}|{}){}", IRI, BNODE.as_str(), WS);
  static ref PROPERTY: String = format!("{}{}", IRI, WS);
  static ref OBJECT: String = format!("(?:{}|{}|{}){}", IRI, BNODE.as_str(), LITERAL.as_str(), WSO);
  static ref GRAPH: String = format!("(?:\\.|(?:(?:{}|{}){}\\.))", IRI, BNODE.as_str(), WSO);

  // full quad regex
  static ref QUAD: String = format!(
      "^{}{}{}{}{}{}$",
      WSO,
      SUBJECT.as_str(),
      PROPERTY.as_str(),
      OBJECT.as_str(),
      GRAPH.as_str(),
      WSO
  );

  static ref QUAD_REGEX: Regex = Regex::new(&QUAD).unwrap();
}

fn match_it_re(re: &Regex, target: &str) {
    for line in target.lines() {
        for _group in re.captures(line) {
            // println!("{:?}", group);
        }
    }
}

fn match_it(db: &Database, scratch: &Scratch, target: &str) {
    // let mut matches = vec![];
    let mut errors = vec![];
    // let mut captures = vec![];
    for line in target.lines() {
        db.scan(
            line,
            &scratch,
            |_id, _from, _to, _flags, captured: Option<&[Capture]>| {
                // matches.push((from, to));
                if let Some(_captured) = captured {
                    assert!(_captured.len() > 1);
                    // println!("VVVVV {}", captured.len());
                    // captures.push(&line[captured[1].range()]);
                    // captures.push(captured.first().expect("captured").range());
                }
                Matching::Continue
            },
            |error_type, id| {
                errors.push((error_type, id));
                Matching::Skip
            },
        )
        .unwrap();
    }
    // println!("CCCCC {:?}", captures);
    // println!("MMMMM {:?}", matches);
    // println!("RRRRR {:?}", errors);
}

fn main() {
    let db: Database = "^([^ ]*)\\s([^ ]*)\\s([^ ]*)\\s([^ ]*)$".parse().unwrap();
    // let db: Database = "test".parse().unwrap();
    let scratch = db.alloc_scratch().unwrap();
    // let mut matches = vec![];
    match_it(&db, &scratch, "some test data");
    // assert_eq!(matches, vec![5..9]);
}

#[bench]
fn bench_hyperscan_trivial(b: &mut Bencher) {
    let dataset_str = "some test data";
    let pattern: Pattern = "(test)".parse().unwrap();
    let db = pattern.with_groups().unwrap();
    let scratch = db.alloc_scratch().unwrap();
    b.iter(|| match_it(&db, &scratch, dataset_str))
}

#[bench]
fn bench_hyperscan_single_quad(b: &mut Bencher) {
    let pattern: Pattern = "^([^ ]*)\\s([^ ]*)\\s([^ ]*)\\s([^ ]*)$".parse().unwrap();
    let db = pattern.with_groups().unwrap();
    let scratch = db.alloc_scratch().unwrap();
    b.iter(|| match_it(&db, &scratch, SINGLE_QUAD))
}

#[bench]
fn bench_hyperscan_15_quads(b: &mut Bencher) {
    let pattern: Pattern = "^([^ ]*)\\s([^ ]*)\\s([^ ]*)\\s([^ ]*)$".parse().unwrap();
    let db = pattern.with_groups().unwrap();
    let scratch = db.alloc_scratch().unwrap();
    b.iter(|| match_it(&db, &scratch, FIFTEEN_QUADS))
}

#[bench]
fn bench_hyperscan_15_quads_full_regex(b: &mut Bencher) {
    let pattern: Pattern = QUAD.parse().unwrap();
    let db = pattern.with_groups().unwrap();
    let scratch = db.alloc_scratch().unwrap();
    b.iter(|| match_it(&db, &scratch, FIFTEEN_QUADS))
}

#[bench]
fn bench_hyperscan_30_quads(b: &mut Bencher) {
    let pattern: Pattern = "^([^ ]*)\\s([^ ]*)\\s([^ ]*)\\s([^ ]*)$".parse().unwrap();
    let db = pattern.with_groups().unwrap();
    let scratch = db.alloc_scratch().unwrap();
    b.iter(|| match_it(&db, &scratch, THIRTY_QUADS))
}

#[bench]
fn bench_hyperscan_30_quads_full_regex(b: &mut Bencher) {
    let pattern: Pattern = QUAD.parse().unwrap();
    let db = pattern.with_groups().unwrap();
    let scratch = db.alloc_scratch().unwrap();
    b.iter(|| match_it(&db, &scratch, THIRTY_QUADS))
}

#[bench]
fn bench_hyperscan_veres_one_did_full_regex(b: &mut Bencher) {
    let pattern: Pattern = QUAD.parse().unwrap();
    let db = pattern.with_groups().unwrap();
    let scratch = db.alloc_scratch().unwrap();
    b.iter(|| match_it(&db, &scratch, VERES_ONE_DID))
}

#[bench]
fn bench_regex_single_quad(b: &mut Bencher) {
    let re = Regex::new("^([^ ]*)\\s([^ ]*)\\s([^ ]*)\\s([^ ]*)$").unwrap();
    b.iter(|| match_it_re(&re, SINGLE_QUAD))
}

#[bench]
fn bench_regex_15_quads(b: &mut Bencher) {
    let re = Regex::new("^([^ ]*)\\s([^ ]*)\\s([^ ]*)\\s([^ ]*)$").unwrap();
    b.iter(|| match_it_re(&re, FIFTEEN_QUADS))
}

#[bench]
fn bench_regex_15_quads_full_regex(b: &mut Bencher) {
    b.iter(|| match_it_re(&QUAD_REGEX, FIFTEEN_QUADS))
}

#[bench]
fn bench_regex_30_quads(b: &mut Bencher) {
    let re = Regex::new("^([^ ]*)\\s([^ ]*)\\s([^ ]*)\\s([^ ]*)$").unwrap();
    b.iter(|| match_it_re(&re, THIRTY_QUADS))
}

#[bench]
fn bench_regex_30_quads_full_regex(b: &mut Bencher) {
    b.iter(|| match_it_re(&QUAD_REGEX, THIRTY_QUADS))
}

#[bench]
fn bench_regex_veres_one_did_full_regex(b: &mut Bencher) {
    b.iter(|| match_it_re(&QUAD_REGEX, VERES_ONE_DID))
}
