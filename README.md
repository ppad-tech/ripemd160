# ppad-ripemd160

A pure Haskell implementation of [RIPEMD-160][ripem] and HMAC-RIPEMD160
on strict and lazy ByteStrings.

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  >
  > -- import qualified
  > import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
  >
  > -- 'hash' and 'hmac' operate on strict bytestrings
  >
  > let hash_s = RIPEMD160.hash "strict bytestring input"
  > let hmac_s = RIPEMD160.hmac "strict secret" "strict bytestring input"
  >
  > -- 'hash_lazy' and 'hmac_lazy' operate on lazy bytestrings
  > -- but note that the key for HMAC is always strict
  >
  > let hash_l = RIPEMD160.hash_lazy "lazy bytestring input"
  > let hmac_l = RIPEMD160.hmac_lazy "strict secret" "lazy bytestring input"
  >
  > -- results are always unformatted 160-bit (20-byte) strict bytestrings
  >
  > import qualified Data.ByteString as BS
  >
  > BS.take 10 hash_s
  "=\211\211\197]\NULJ\223n\223"
  > BS.take 10 hmac_l
  "\154\248\145[\196\ETX\f\ESC\NULs"
  >
  > -- you can use third-party libraries for rendering if needed
  > -- e.g., using base16-bytestring:
  >
  > import qualified Data.ByteString.Base16 as B16
  >
  > B16.encode hash_s
  "3dd3d3c55d004adf6edf9e11cb01f9ac9c56441f"
  > B16.encode hmac_l
  "9af8915bc4030c1b007323c8531b3129d82f50bd"
```

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/ripemd160][hadoc].

## Performance

The aim is best-in-class performance for pure, highly-auditable Haskell
code.

Current benchmark figures on my mid-2020 MacBook Air look like (use
`cabal bench` to run the benchmark suite):

```
  benchmarking ppad-ripemd160/RIPEMD160 (32B input)/hash
  time                 1.115 μs   (1.109 μs .. 1.122 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 1.123 μs   (1.117 μs .. 1.130 μs)
  std dev              19.84 ns   (16.75 ns .. 23.55 ns)
  variance introduced by outliers: 19% (moderately inflated)

  benchmarking ppad-ripemd160/RIPEMD160 (32B input)/hash_lazy
  time                 1.072 μs   (1.060 μs .. 1.085 μs)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 1.073 μs   (1.066 μs .. 1.082 μs)
  std dev              27.29 ns   (23.35 ns .. 31.28 ns)
  variance introduced by outliers: 33% (moderately inflated)

  benchmarking ppad-ripemd160/HMAC-RIPEMD160 (32B input)/hmac
  time                 3.941 μs   (3.919 μs .. 3.963 μs)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 3.997 μs   (3.972 μs .. 4.037 μs)
  std dev              111.0 ns   (71.80 ns .. 191.1 ns)
  variance introduced by outliers: 34% (moderately inflated)

  benchmarking ppad-ripemd160/HMAC-RIPEMD160 (32B input)/hmac_lazy
  time                 3.944 μs   (3.912 μs .. 3.991 μs)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 3.982 μs   (3.955 μs .. 4.012 μs)
  std dev              96.66 ns   (83.81 ns .. 117.3 ns)
  variance introduced by outliers: 28% (moderately inflated)
```

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be challenging to achieve.

The RIPEMD-160 functions pass the vectors present in the [official
spec][ripem], and the HMAC-RIPEMD160 functions pass all vectors found
contained in [RFC2286][rfc22].

If you discover any vulnerabilities, please disclose them via
security@ppad.tech.

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal repl ppad-ripemd160
```

to get a REPL for the main library.

[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/ripemd160
[ripem]: https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
[rfc22]: https://www.rfc-editor.org/rfc/rfc2286.html#section-2
