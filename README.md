# Charm

| Branch | Status                                                                                         |
| ------ | ---------------------------------------------------------------------------------------------- |
| `dev`  | ![Build Status](https://github.com/JHUISI/charm/actions/workflows/ci.yml/badge.svg?branch=dev) |

Charm is a framework for rapidly prototyping advanced cryptosystems. Based on the Python language, it was designed from the ground up to minimize development time and code complexity while promoting the reuse of components.

Charm uses a hybrid design: performance intensive mathematical operations are implemented in native C modules, while cryptosystems themselves are written in a readable, high-level language. Charm additionally provides a number of new components to facilitate the rapid development of new schemes and protocols.

Features of Charm include:

- Support for various mathematical settings, including integer rings/fields, bilinear and non-bilinear Elliptic Curve groups
- Base crypto library, including symmetric encryption schemes, hash functions, PRNGs
- Standard APIs for constructions such as digital signature, encryption, commitments
- A "protocol engine" to simplify the process of implementing multi-party protocols
- An integrated compiler for interactive and non-interactive ZK proofs
- Integrated benchmarking capability

## Hybrid Encryption Benchmarks

This repository includes comprehensive benchmark implementations for hybrid encryption schemes combining Identity-Based Encryption (IBE) and Attribute-Based Encryption (ABENC) with symmetric encryption for efficient large data encryption.

### Available Benchmarks

#### 1. Hybrid IBE Encryption Benchmark

- **File**: `benchmark_hybrid_encryption.py`
- **Runner**: `run_benchmark.py`
- **Scheme**: Boneh-Franklin IBE (BF01) + AES symmetric encryption
- **Description**: Encrypts a symmetric key using IBE and data using AES, providing both security and efficiency

#### 2. Hybrid ABENC Encryption Benchmark

- **File**: `benchmark_hybrid_abenc_dacmacs.py`
- **Runner**: `run_abenc_benchmark.py`
- **Scheme**: DACMACS ABENC + AES symmetric encryption
- **Description**: Encrypts using attribute-based policies with hybrid approach for large data

### Benchmark Features

- **Performance Metrics**: Measures encryption/decryption time, CPU usage, and memory consumption
- **Data Sizes**: Tests from 1KB to 10MB data sizes
- **Reliability**: Includes retry mechanisms and error handling
- **Output Formats**: JSON results and CSV export for analysis
- **Comprehensive Monitoring**: Real-time CPU and memory tracking during operations

### Usage

#### Run Hybrid IBE Benchmark

```bash
python run_benchmark.py
```

#### Run Hybrid ABENC Benchmark

```bash
python run_abenc_benchmark.py
```

#### Generate CSV Reports

```bash
python create_benchmark_csv.py
```

### Output Files

- `benchmark_results.json` - IBE benchmark results
- `benchmark_abenc_results.json` - ABENC benchmark results
- `benchmark_results.csv` - Formatted CSV for IBE results
- `benchmark_results_transposed.csv` - Alternative CSV format

### Benchmark Architecture

Both benchmarks implement a hybrid encryption approach:

1. **Key Generation**: Generate symmetric encryption key
2. **IBE/ABENC Encryption**: Encrypt the symmetric key using IBE or ABENC
3. **Symmetric Encryption**: Encrypt large data using AES with the symmetric key
4. **Decryption**: Reverse process with performance monitoring

### Test Environment

- **Elliptic Curve**: SS512 pairing group
- **Symmetric Cipher**: AES encryption via Charm's SymmetricCryptoAbstraction
- **Data Sizes**: 1KB, 10KB, 100KB, 250KB, 500KB, 750KB, 1MB, 5MB, 7MB, 10MB
- **Iterations**: 3 iterations per data size for statistical accuracy

# Documentation

For complete install, see our [documentation](https://jhuisi.github.io/charm/install_source.html).

# Pull Requests

We welcome and encourage scheme contributions. If you'd like your scheme implementation included in the Charm distribution, please note a few things.
Schemes in the dev branch are Python 3.x only and ones in the 2.7-dev branch are Python 2.x. For your scheme to be included in unit tests (`make test`), you must include a doctest at a minimum (see schemes in the charm/schemes directory).

# Schemes

We have provided several cryptographic scheme [examples](https://jhuisi.github.io/charm/schemes.html) to get you going. If this doesn't help, then feel free to reach us for questions and/or comments at support@charm-crypto.com.

If you're using Charm to implement schemes, we want to know what your experience is with our framework. Your feedback is very valuable to us!

# Quick Install & Test

Installing Charm from source is straightforward. First, verify that you have installed the following dependencies:

- [GMP 5.x](http://gmplib.org/)
- [PBC 0.5.14](http://crypto.stanford.edu/pbc/download.html)
- [OpenSSL](http://www.openssl.org/source/)
- [PyParsing 2.1.5](https://pypi.org/project/pyparsing/2.1.5/)
- [Hypothesis](https://pypi.org/project/hypothesis/)

After that, you may proceed to install a basic configuration of Charm as follows:

- `./configure.sh` (include `--enable-darwin` if running Mac OS X)
- `make install` (may require super-user privileges)
- `make test` (may also require super-user privileges)

If most (or all) Python tests pass, then the Charm installation was successful. Enjoy!

# Licensing

Charm is released under an LGPL version 3 license due to libraries that we build on. See the `LICENSE.txt` for details.

