### Benches
`PKG_CONFIG_PATH=/home/matt/dev/hyperscan/build/chimera cargo bench -- --nocapture`

```
test bench_hyperscan_15_quads    ... bench:       5,484 ns/iter (+/- 438)
test bench_hyperscan_30_quads    ... bench:      12,159 ns/iter (+/- 360)
test bench_hyperscan_single_quad ... bench:         450 ns/iter (+/- 13)
test bench_hyperscan_trivial     ... bench:         207 ns/iter (+/- 9)
test bench_regex_15_quads        ... bench:      23,531 ns/iter (+/- 941)
test bench_regex_30_quads        ... bench:      38,631 ns/iter (+/- 2,216)
test bench_regex_single_quad     ... bench:       1,106 ns/iter (+/- 212)
```

### Build
```
PKG_CONFIG_PATH=/home/matt/dev/hyperscan/build/chimera cargo build
```

### Background
- https://rust-leipzig.github.io/regex/2017/03/28/comparison-of-regex-engines/
- https://www.hyperscan.io/
- https://www.usenix.org/system/files/nsdi19-wang-xiang.pdf
- http://intel.github.io/hyperscan/dev-reference/index.html
- https://github.com/flier/rust-hyperscan

