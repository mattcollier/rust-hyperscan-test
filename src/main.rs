#![feature(test)]
extern crate test;

use hyperscan::prelude::*;
use test::Bencher;

fn match_it(db: &Database<hyperscan::Block>, scratch: &Scratch) {
    let mut matches = vec![];
    let dataset_str = r#"_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/webledger#ContinuityMergeEvent> .
_:b0 <https://w3id.org/security#proof> _:b1 .
_:b0 <https://w3id.org/webledger#parentHash> "zQmPkZrQs9dyezAQkVniqkMjm5nP3cdWFBzNsnnFLrsNf9u" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmYDcw6hXTZHCYaPyuGLCo8jcNREidQs4ikwKdVyS5uwKA" .
_:b0 <https://w3id.org/webledger#parentHash> "zQma45eMXmzKBXYwLdU7FvAEW3ekMy4fJjqEQVhYQFgwYAP" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmb6eicGxT6FAAZdxEzam2JpPu8ajiMJYhzPnhgHJJKh8f" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmc6b7weYQEu2NBDK9DB4HBc4bt2qQGbkvkEZBW6ajJ5F7" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmdxvSCwPjTvx3SAN2XHZ4uQpHKpbnHmns9BF8uZASW6Lx" .
_:b0 <https://w3id.org/webledger#parentHash> "zQmePs3zy2fLPEsBXqGn2LPWSGYbzPy7CZTTz1f2ng3ysph" .
_:b0 <https://w3id.org/webledger#treeHash> "zQmPkZrQs9dyezAQkVniqkMjm5nP3cdWFBzNsnnFLrsNf9u" .
_:b2 <http://purl.org/dc/terms/created> "2018-12-21T23:40:20Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:b1 .
_:b2 <http://purl.org/dc/terms/creator> <https://bedrock.localhost:18443/consensus/continuity2017/voters/z6MkkabTusFkLnquxwHwCm28v59UX3P9Pn5scvc7fCaNvWUL> _:b1 .
_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2018> _:b1 .
_:b2 <https://w3id.org/security#jws> "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..JJ5c7mF7ru9XhPtrNqj1s6J74yqOC0HcNyK_Wa0OcfDaiODZFIJ2dXIrc_qqqvTWynIqJid6yXkKsGAzyi_HDQ" _:b1 .
"#;

    for p in dataset_str.lines() {
        db.scan(p, &scratch, |id, from, to, flags| {
            println!("found pattern #{} @ [{}, {})", id, from, to);

            matches.push(from..to);

            Matching::Continue
        }).unwrap();
    }
}

fn main() {
    let pattern = pattern! {"^([^ ]*)\\s([^ ]*)\\s([^ ]*)\\s([^ ]*)$"; CASELESS | SOM_LEFTMOST};
    // let pattern = pattern! {"test"; CASELESS | SOM_LEFTMOST};
    let db: BlockDatabase = pattern.build().unwrap();
    let scratch = db.alloc_scratch().unwrap();
    // let mut matches = vec![];
    match_it(&db, &scratch);



    // assert_eq!(matches, vec![5..9]);
}


#[bench]
fn bench_match_it(b: &mut Bencher) {
    let pattern = pattern! {"^([^ ]*)\\s([^ ]*)\\s([^ ]*)\\s([^ ]*)$"; CASELESS | SOM_LEFTMOST};
    // let pattern = pattern! {"test"; CASELESS | SOM_LEFTMOST};
    let db: BlockDatabase = pattern.build().unwrap();
    let scratch = db.alloc_scratch().unwrap();
    // let mut matches = vec![];
    b.iter(|| match_it(&db, &scratch))
}
