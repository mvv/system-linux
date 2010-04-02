{-# LANGUAGE CPP, ForeignFunctionInterface, TemplateHaskell #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- | This module provides bindings to eventfd(2).
module System.Linux.EventFd (
    CreateFlags,
    nonBlockingFlag,
    closeOnExecFlag,

    create,
    readValue,
    addToValue
  ) where

import Data.Word (Word64)
import Data.Flags ()
import Data.Flags.TH (bitmaskWrapper)
import Foreign.Storable (Storable(..))
import Foreign.Ptr (Ptr, castPtr)
import Foreign.C.Types (CInt, CUInt, CSize)
import Foreign.C.Error (throwErrnoIf_, throwErrnoIfMinus1)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (with)
import System.Posix.Types (Fd(..), CSsize)

#include <sys/eventfd.h>

$(bitmaskWrapper "CreateFlags" ''CInt [''Storable]
    [("nonBlockingFlag", #{const EFD_NONBLOCK}),
     ("closeOnExecFlag", #{const EFD_CLOEXEC})])

-- | Create an eventfd file descriptor. See /eventfd(2)/.
create :: CUInt -- ^ Initial value of the counter.
       -> CreateFlags
       -> IO Fd
create value flags =
  throwErrnoIfMinus1 "EventFd.create" $ c_eventfd value flags

-- | Read the counter value and reset it to zero.
--   Blocks if the counter value is already a zero.
readValue :: Fd -> IO Word64
readValue fd =
  alloca $ \p -> do
    throwErrnoIf_ (/= 8) "EventFd.readValue" $ c_read fd (castPtr p) 8
    peek p

-- | Add the specified value to the current counter value.
--   Blocks if the result exceeds @0xFFFFFFFFFFFFFFFE@.
addToValue :: Fd -> Word64 -> IO ()
addToValue fd value = do
  with value $ \p ->
    throwErrnoIf_ (/= 8) "EventFd.addToValue" $ c_write fd (castPtr p) 8

foreign import ccall unsafe "eventfd"
  c_eventfd :: CUInt -> CreateFlags -> IO Fd

foreign import ccall unsafe "read"
  c_read :: Fd -> Ptr () -> CSize -> IO CSsize
foreign import ccall unsafe "write"
  c_write :: Fd -> Ptr () -> CSize -> IO CSsize

