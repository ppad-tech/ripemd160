{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL

main :: IO ()
main = defaultMain [
    suite
  ]

suite :: Benchmark
suite = env setup $ \ ~(bs, bl) ->
    bgroup "ppad-ripemd160" [
      bgroup "RIPEMD160 (32B input)" [
        bench "hash" $ whnf RIPEMD160.hash bs
      , bench "hash_lazy" $ whnf RIPEMD160.hash_lazy bl
      ]
    , bgroup "HMAC-RIPEMD160 (32B input)" [
        bench "hmac" $ whnf (RIPEMD160.hmac "key") bs
      , bench "hmac_lazy" $ whnf (RIPEMD160.hmac_lazy "key") bl
      ]
    ]
  where
    setup = do
      let bs_32B = BS.replicate 32 0
          bl_32B = BL.fromStrict bs_32B
      pure (bs_32B, bl_32B)

