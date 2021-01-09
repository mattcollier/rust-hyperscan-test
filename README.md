### Benches
`PKG_CONFIG_PATH=/home/matt/dev/hyperscan/build/chimera cargo bench -- --nocapture`

```
test bench_hyperscan_15_quads                 ... bench:       5,386 ns/iter (+/- 137)
test bench_hyperscan_15_quads_full_regex      ... bench:      16,511 ns/iter (+/- 831)
test bench_hyperscan_30_quads                 ... bench:      11,783 ns/iter (+/- 411)
test bench_hyperscan_30_quads_full_regex      ... bench:      31,354 ns/iter (+/- 1,687)
test bench_hyperscan_single_quad              ... bench:         437 ns/iter (+/- 17)
test bench_hyperscan_trivial                  ... bench:         218 ns/iter (+/- 4)
test bench_hyperscan_veres_one_did_full_regex ... bench:      29,302 ns/iter (+/- 1,117)
test bench_regex_15_quads                     ... bench:      23,968 ns/iter (+/- 713)
test bench_regex_15_quads_full_regex          ... bench:      23,019 ns/iter (+/- 1,951)
test bench_regex_30_quads                     ... bench:      38,879 ns/iter (+/- 1,314)
test bench_regex_30_quads_full_regex          ... bench:      40,293 ns/iter (+/- 1,065)
test bench_regex_single_quad                  ... bench:       1,106 ns/iter (+/- 54)
test bench_regex_veres_one_did_full_regex     ... bench:      64,839 ns/iter (+/- 2,920)
```

### Build
```
PKG_CONFIG_PATH=/home/matt/dev/hyperscan/build/chimera cargo build
```

### Build Hyperscan with Chimera
The base Hyperscan API does not support regex capture groups. The add-on
Chimera API provides this functionality.

See: http://intel.github.io/hyperscan/dev-reference/chimera.html

```
git clone https://github.com/intel/hyperscan.git
cd hyperscan
# v8.44 is latest
wget https://ftp.pcre.org/pub/pcre/pcre-8.44.tar.gz
mkdir pcre
tar xvf pcre-8.44.tar.gz --strip-components=1 --directory pcre

mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=`pwd`
# set -j CPUs appropriately
make -j 12
```

### Background
- https://rust-leipzig.github.io/regex/2017/03/28/comparison-of-regex-engines/
- https://www.hyperscan.io/
- https://www.usenix.org/system/files/nsdi19-wang-xiang.pdf
- http://intel.github.io/hyperscan/dev-reference/index.html
- https://github.com/flier/rust-hyperscan

