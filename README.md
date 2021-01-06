### Benches
`PKG_CONFIG_PATH=/home/matt/dev/hyperscan/build/chimera cargo bench -- --nocapture`

```
test bench_hyperscan_15_quads    ... bench:       5,444 ns/iter (+/- 217)
test bench_hyperscan_30_quads    ... bench:      11,907 ns/iter (+/- 191)
test bench_hyperscan_single_quad ... bench:         447 ns/iter (+/- 25)
test bench_hyperscan_trivial     ... bench:         208 ns/iter (+/- 13)
test bench_regex_15_quads        ... bench:      23,352 ns/iter (+/- 401)
test bench_regex_30_quads        ... bench:      38,216 ns/iter (+/- 987)
test bench_regex_single_quad     ... bench:       1,083 ns/iter (+/- 22)
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

