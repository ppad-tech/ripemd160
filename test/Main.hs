{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module Main where

import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base16 as B16
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain $ testGroup "ppad-ripemd160" [
    unit_tests
  ]

unit_tests :: TestTree
unit_tests = testGroup "unit tests" [
    testGroup "hash" [
      cmp_hash "hv0" hv0_put hv0_pec
    , cmp_hash "hv1" hv1_put hv1_pec
    , cmp_hash "hv2" hv2_put hv2_pec
    , cmp_hash "hv3" hv3_put hv3_pec
    , cmp_hash "hv4" hv4_put hv4_pec
    , cmp_hash "hv5" hv5_put hv5_pec
    , cmp_hash "hv6" hv6_put hv6_pec
    , cmp_hash "hv7" hv7_put hv7_pec
    , cmp_hash "hv8" hv8_put hv8_pec
    ]
  , testGroup "hash_lazy" [
      cmp_hash_lazy "hv0" hv0_put hv0_pec
    , cmp_hash_lazy "hv1" hv1_put hv1_pec
    , cmp_hash_lazy "hv2" hv2_put hv2_pec
    , cmp_hash_lazy "hv3" hv3_put hv3_pec
    , cmp_hash_lazy "hv4" hv4_put hv4_pec
    , cmp_hash_lazy "hv5" hv5_put hv5_pec
    , cmp_hash_lazy "hv6" hv6_put hv6_pec
    , cmp_hash_lazy "hv7" hv7_put hv7_pec
    , cmp_hash_lazy "hv8" hv8_put hv8_pec
    ]
  , testGroup "hmac" [
      cmp_hmac "hmv1" hmv1_key hmv1_put hmv1_pec
    , cmp_hmac "hmv2" hmv2_key hmv2_put hmv2_pec
    , cmp_hmac "hmv3" hmv3_key hmv3_put hmv3_pec
    , cmp_hmac "hmv4" hmv4_key hmv4_put hmv4_pec
    , cmp_hmac "hmv5" hmv5_key hmv5_put hmv5_pec
    , cmp_hmac "hmv6" hmv6_key hmv6_put hmv6_pec
    , cmp_hmac "hmv7" hmv7_key hmv7_put hmv7_pec
    ]
  , testGroup "hmac_lazy" [
      cmp_hmac_lazy "hmv1" hmv1_key hmv1_put hmv1_pec
    , cmp_hmac_lazy "hmv2" hmv2_key hmv2_put hmv2_pec
    , cmp_hmac_lazy "hmv3" hmv3_key hmv3_put hmv3_pec
    , cmp_hmac_lazy "hmv4" hmv4_key hmv4_put hmv4_pec
    , cmp_hmac_lazy "hmv5" hmv5_key hmv5_put hmv5_pec
    , cmp_hmac_lazy "hmv6" hmv6_key hmv6_put hmv6_pec
    , cmp_hmac_lazy "hmv7" hmv7_key hmv7_put hmv7_pec
    ]
  ]

cmp_hash :: String -> BS.ByteString -> BS.ByteString -> TestTree
cmp_hash msg put pec = testCase msg $ do
  let out = B16.encode (RIPEMD160.hash put)
  assertEqual mempty pec out

cmp_hash_lazy :: String -> BS.ByteString -> BS.ByteString -> TestTree
cmp_hash_lazy msg (BL.fromStrict -> put) pec = testCase msg $ do
  let out = B16.encode (RIPEMD160.hash_lazy put)
  assertEqual mempty pec out

hv0_put, hv0_pec :: BS.ByteString
hv0_put = mempty
hv0_pec = "9c1185a5c5e9fc54612808977ee8f548b2258d31"

hv1_put, hv1_pec :: BS.ByteString
hv1_put = "a"
hv1_pec = "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"

hv2_put, hv2_pec :: BS.ByteString
hv2_put = "abc"
hv2_pec = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"

hv3_put, hv3_pec :: BS.ByteString
hv3_put = "message digest"
hv3_pec = "5d0689ef49d2fae572b881b123a85ffa21595f36"

hv4_put, hv4_pec :: BS.ByteString
hv4_put = "abcdefghijklmnopqrstuvwxyz"
hv4_pec = "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"

hv5_put, hv5_pec :: BS.ByteString
hv5_put = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
hv5_pec = "12a053384a9c0c88e405a06c27dcf49ada62eb2b"

hv6_put, hv6_pec :: BS.ByteString
hv6_put = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
hv6_pec = "b0e20b6e3116640286ed3a87a5713079b21f5189"

hv7_put, hv7_pec :: BS.ByteString
hv7_put = "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
hv7_pec = "9b752e45573d4b39f4dbd3323cab82bf63326bfb"

hv8_put, hv8_pec :: BS.ByteString
hv8_put = BS.replicate 1000000 0x61
hv8_pec = "52783243c1697bdbe16d37f97f68f08325dc1528"

-- vectors from
--
-- https://www.rfc-editor.org/rfc/rfc2286.html#section-2

cmp_hmac
  :: String -> BS.ByteString -> BS.ByteString -> BS.ByteString -> TestTree
cmp_hmac msg key put pec = testCase msg $ do
  let out = B16.encode (RIPEMD160.hmac key put)
  assertEqual mempty pec out

cmp_hmac_lazy
  :: String -> BS.ByteString -> BS.ByteString -> BS.ByteString -> TestTree
cmp_hmac_lazy msg key (BL.fromStrict -> put) pec = testCase msg $ do
  let out = B16.encode (RIPEMD160.hmac_lazy key put)
  assertEqual mempty pec out

decodeLenient :: BS.ByteString -> BS.ByteString
decodeLenient bs = case B16.decode bs of
  Nothing -> error "bang"
  Just b -> b

hmv1_key :: BS.ByteString
hmv1_key = decodeLenient "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"

hmv1_put :: BS.ByteString
hmv1_put = "Hi There"

hmv1_pec :: BS.ByteString
hmv1_pec = "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668"

hmv2_key :: BS.ByteString
hmv2_key = "Jefe"

hmv2_put :: BS.ByteString
hmv2_put = "what do ya want for nothing?"

hmv2_pec :: BS.ByteString
hmv2_pec = "dda6c0213a485a9e24f4742064a7f033b43c4069"

hmv3_key :: BS.ByteString
hmv3_key = decodeLenient "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

hmv3_put :: BS.ByteString
hmv3_put = decodeLenient "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

hmv3_pec :: BS.ByteString
hmv3_pec = "b0b105360de759960ab4f35298e116e295d8e7c1"

hmv4_key :: BS.ByteString
hmv4_key = decodeLenient "0102030405060708090a0b0c0d0e0f10111213141516171819"

hmv4_put :: BS.ByteString
hmv4_put = decodeLenient "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

hmv4_pec :: BS.ByteString
hmv4_pec = "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4"

hmv5_key :: BS.ByteString
hmv5_key = decodeLenient "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"

hmv5_put :: BS.ByteString
hmv5_put = "Test With Truncation"

hmv5_pec :: BS.ByteString
hmv5_pec = "7619693978f91d90539ae786500ff3d8e0518e39"

hmv6_key :: BS.ByteString
hmv6_key = decodeLenient "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

hmv6_put :: BS.ByteString
hmv6_put = "Test Using Larger Than Block-Size Key - Hash Key First"

hmv6_pec :: BS.ByteString
hmv6_pec = "6466ca07ac5eac29e1bd523e5ada7605b791fd8b"

hmv7_key :: BS.ByteString
hmv7_key = hmv6_key

hmv7_put :: BS.ByteString
hmv7_put = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"

hmv7_pec :: BS.ByteString
hmv7_pec = "69ea60798d71616cce5fd0871e23754cd75d5a0a"

