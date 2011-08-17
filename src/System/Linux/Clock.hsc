{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE CPP #-}

module System.Linux.Clock (
    monotonicRawClock
  ) where

import System.Posix.Clock (Clock(..))

#include <time.h>

monotonicRawClock ∷ Clock
monotonicRawClock = Clock #{const CLOCK_MONOTONIC_RAW}

