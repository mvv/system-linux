{-# LANGUAGE CPP, ForeignFunctionInterface, TemplateHaskell #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- | This module provides bindings to timerfd functions.
module System.Linux.TimerFd (
    CreateFlags,
    nonBlockingFlag,
    closeOnExecFlag,

    create,
    configure,
    timeLeft,
    expirationCnt
  ) where

import Data.Word (Word64)
import Data.Flags ()
import Data.Flags.TH (bitmaskWrapper)
import Foreign.Storable (Storable(..))
import Foreign.Ptr (Ptr, castPtr)
import Foreign.C.Types (CInt, CSize)
import Foreign.C.Error (throwErrnoIf_, throwErrnoIfMinus1, throwErrnoIfMinus1_)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (with)
import System.Posix.Types (Fd(..), CSsize)
import System.Posix.Timer (TimeSpec(..), ITimerSpec(..))

#include <sys/timerfd.h>

$(bitmaskWrapper "CreateFlags" ''CInt [''Storable]
    [("nonBlockingFlag", #{const TFD_NONBLOCK}),
     ("closeOnExecFlag", #{const TFD_CLOEXEC})])

-- | Create a timerfd file descriptor. See /timerfd_create(2)/.
create :: Bool -- ^ Whether to use the realtime clock.
       -> CreateFlags
       -> IO Fd
create realtime flags =
  throwErrnoIfMinus1 "TimerFd.create" $
    c_timerfd_create (if realtime then #{const CLOCK_REALTIME}
                                  else #{const CLOCK_MONOTONIC}) flags

-- | Configure the associated timer. See /timerfd_settime(2)/.
configure :: Fd -- ^ Timerfd file descriptor.
          -> Bool -- ^ Whether the expiration time is absolute.
          -> TimeSpec -- ^ Expiration time. Zero value disarms the timer.
          -> TimeSpec -- ^ Interval between subsequent expirations.
          -> IO (TimeSpec, TimeSpec)
configure fd absolute value interval =
  with (ITimerSpec interval value) $ \pNew ->
    alloca $ \pOld -> do
      throwErrnoIfMinus1_ "TimerFd.configure" $
        c_timerfd_settime
          fd (if absolute then #{const TFD_TIMER_ABSTIME} else 0) pNew pOld
      (ITimerSpec oldInterval oldValue) <- peek pOld
      return (oldValue, oldInterval)
                               
-- | Get the amount of time left until the next expiration and the interval
--   between the subsequent expirations. See /timerfd_gettime(2)/.
timeLeft :: Fd -> IO (TimeSpec, TimeSpec)
timeLeft fd = do
  alloca $ \p -> do
    throwErrnoIfMinus1_ "TimerFd.timeLeft" $ c_timerfd_gettime fd p
    (ITimerSpec interval value) <- peek p
    return (value, interval)

-- | Get the associated timer expiration count (resets the counter).
--   Blocks if no expirations have occurred.
expirationCnt :: Fd -> IO Word64
expirationCnt fd =
  alloca $ \p -> do
    throwErrnoIf_ (/= 8) "TimerFd.readExpirationCnt" $
      c_read fd (castPtr p) 8
    peek p

foreign import ccall unsafe "timerfd_create"
  c_timerfd_create :: CInt -> CreateFlags -> IO Fd
foreign import ccall unsafe "timerfd_settime"
  c_timerfd_settime ::
    Fd -> CInt -> Ptr ITimerSpec -> Ptr ITimerSpec -> IO CInt
foreign import ccall unsafe "timerfd_gettime"
  c_timerfd_gettime :: Fd -> Ptr ITimerSpec -> IO CInt

foreign import ccall unsafe "read"
  c_read :: Fd -> Ptr () -> CSize -> IO CSsize

