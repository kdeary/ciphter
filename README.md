# ciphter

**ciphter** is a command-line cryptography analysis and processing tool written in C. It helps identify common encodings and hashes, and features a powerful solving engine that uses a priority-queue based search to decode multi-layered ciphertexts.

## Features

- **Automated Analysis**: Quickly detect if a string is Hex, Base64, English text, or an MD5/SHA-256 hash.
- **Solving Engine**: Iteratively apply transformation algorithms (solvers) to find the most likely original plaintext.
- **Deep Search**: Chain multiple decoders (e.g., HEX -> MORSE -> BASE64) to crack nested encodings.
- **Path Pruning**: Limit search space with heap size constraints and fitness thresholds.
- **Crib Support**: Filter results by searching for known strings (cribs).

## Installation

### Prerequisites

- GCC (or any C compiler)
- Make
- `argp` library (standard on most Linux distributions, available via `libc-dev`)

### Build

Clone the repository and run:

```bash
make
```

The binary will be created in `bin/ciphter`.

## Usage

Ciphter has two main operating modes: `analyze` and `solve`.

### 1. Analysis Mode

Analyzes an input to find the probability of it being a certain format.

```bash
./bin/ciphter -t A -i "48656c6c6f"
```

### 2. Solving Mode

Decrypts input by trying various combinations of algorithms.

```bash
./bin/ciphter -t S -i "UzBoSlpXNHUgYm05MElHUnZkVzVmY0dSbVp3PT0="
```

## Options Reference

| Option | Short | Description |
| :--- | :--- | :--- |
| `--task` | `-t` | Task type: `A` for analyze, `S` for solve. |
| `--input` | `-i` | String to process. |
| `--input-file`| `-I` | File to process. |
| `--algorithms` | `-a` | Specific algorithms to use (default: "common"). |
| `--depth` | `-d` | Max recursion depth for solver combinations. |
| `--keys` | `-k` | Raw keys for algorithms like Vigenere (pipe-separated). |
| `--keyfile` | `-K` | File containing keys (one per line). |
| `--heap-size` | `-H` | Max number of paths to track in memory (default: 1000). |
| `--crib` | `-c` | Known string to search for to filter results. |
| `--english` | `-E` | English quality threshold (0-100). |
| `--timeout` | `-T` | Timeout in seconds (default: 10). |
| `--verbose` | `-v` | Show debug logs. |

## Supported Algorithms

### Analyzers
- English Text Detection
- Hexadecimal
- Base64
- SHA-256
- MD5

### Solvers
- **Encodings**: Hex, Base64, Binary, Octal, Morse Code, Base (2-36) conversion.
- **Ciphers**: Affine, Vigenere, Railfence.

## Examples

**Cracking a nested encoding:**
```bash
$ bin/ciphter -tS -i "0101000100110001010100100100011101001100010101010101101001001101010100010101010101100011011101000100110101010100010010010111101001001110010000010011110100111101" -d 2
[INFO] Running solving on input: "0101000100110001010100100100011101001100010101010101101001..." (Timeout: 10s)
[INFO] Running solvers...

--- Best Result (Agg:3.00) IS_ENGLISH_MODE=0 ---
[2][100%]        "CTF-FLAG-1234"
Method: "CIPHERTEXT -> BINARY -> BASE64"
----------------------------------

[INFO] Solving process finished.
```

**Using a key for Vigenere decryption:**
```bash
$ bin/ciphter -tS -i "NGQgNTggNDQgMmQgNTAgNTAgNTkgNTEgMmQgMzEgMzIgMzMgMzQ=" -d 3 -k "key" -c "CTF-"
[INFO] Running solving on input: "NGQgNTggNDQgMmQgNTAgNTAgNTkgNTEgMmQgMzEgMzIgMzMgMzQ=" (Timeout: 10s)
[INFO] Running solvers...
[3][300%][Agg:4.52]      [CRIB FOUND] "CTF-FLAG-1234" - Method: "CIPHERTEXT -> BASE64 -> HEX -> VIGENERE(key)"

--- Best Result (Agg:4.52) IS_ENGLISH_MODE=0 ---
[3][300%]        "CTF-FLAG-1234"
Method: "CIPHERTEXT -> BASE64 -> HEX -> VIGENERE(key)"
----------------------------------

[INFO] Solving process finished.
```

**Filtering for a specific word (Crib):**
```bash
$ bin/ciphter -tS -i "MDAwMTAxMDEwMTAwMDExMDAxMTExMDEwMTAwMDExMTAxMDAxMTAxMDEwMTExMTEwMTAxMDExMTEwMTAxMDEwMDAwMDEwMDAxMDEwMDAxMDEwMTAwMDAwMTAwMDEwMTAwMDEwMTAxMTAxMTExMDAwMTExMDEwMTAxMDAxMTExMTAxMDAxMDAxMTExMTExMDAxMTAwMDEwMTAxMDAxMDEwMA==" -d 8 -k "key" -c "CTF-"
[INFO] Running solving on input: "MDAwMTAxMDEwMTAwMDExMDAxMTExMDEwMTAwMDExMTAxMDAxMTAxMDEwMT..." (Timeout: 10s)
[INFO] Running solvers...
[5][300%][Agg:3003.79]   [CRIB FOUND] "CTF-FLAG-1234" - Method: "CIPHERTEXT -> BASE64 -> RAILFENCE k=5 o=6 -> BINARY -> BASE64 -> XOR(key)" [INFO] Timeout reached (10s). Stopping...

--- Best Result (Agg:3003.79) IS_ENGLISH_MODE=0 ---
[5][300%]        "CTF-FLAG-1234"
Method: "CIPHERTEXT -> BASE64 -> RAILFENCE k=5 o=6 -> BINARY -> BASE64 -> XOR(key)"
----------------------------------

[INFO] Solving process finished.
```

## License

This project is open-source. See file headers for specific library licenses (SDS, Minheap).
