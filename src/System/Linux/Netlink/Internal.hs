{-# LANGUAGE UnicodeSyntax #-}

module System.Linux.Netlink.Internal (
    align4
  ) where

import Data.Bits

align4 ∷ (Num n, Bits n) ⇒ n → n
align4 n = (n + 3) .&. complement 3
{-# INLINE align4 #-}

