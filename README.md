# ripemd160

[![](https://img.shields.io/hackage/v/ppad-ripemd160?color=blue)](https://hackage.haskell.org/package/ppad-ripemd160)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-ripemd160-lightblue)](https://docs.ppad.tech/ripemd160)

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
  > -- e.g., using ppad-base16:
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
  time                 786.6 ns   (778.0 ns .. 796.7 ns)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 778.6 ns   (775.3 ns .. 784.2 ns)
  std dev              13.85 ns   (9.858 ns .. 22.05 ns)
  variance introduced by outliers: 20% (moderately inflated)

  benchmarking ppad-ripemd160/HMAC-RIPEMD160 (32B input)/hmac
  time                 2.933 μs   (2.906 μs .. 2.974 μs)
                       0.999 R²   (0.999 R² .. 0.999 R²)
  mean                 3.002 μs   (2.978 μs .. 3.022 μs)
  std dev              74.97 ns   (62.74 ns .. 89.91 ns)
  variance introduced by outliers: 30% (moderately inflated)
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
