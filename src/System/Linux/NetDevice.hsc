{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DoAndIfThenElse #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE FlexibleContexts #-}

module System.Linux.NetDevice (
    IfIndex(..),
    getIfIndex,
    getIfName
  ) where

import Data.Typeable (Typeable)
import Data.Word (Word32)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
import qualified Data.ByteString.Internal as BS
import Control.Applicative ((<$>))
import Control.Monad (void)
import Control.Monad.Base
#if __GLASGOW_HASKELL__ >= 703
import Foreign.C.Types (CInt(..))
#else
import Foreign.C.Types (CInt)
#endif
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (Storable(..))
import Foreign.Marshal.Alloc (allocaBytesAligned)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.C.Error (eNODEV, getErrno, errnoToIOError)
import System.Posix.Types (Fd(..))
import System.Posix.Socket (Socket, withSocketFd)

#include <sys/ioctl.h>
#include <net/if.h>
#include <system-linux.macros.h>

newtype IfIndex = IfIndex { unIfIndex ∷ Word32 }
                  deriving (Typeable, Eq, Ord, Show)

getIfIndex ∷ MonadBase IO μ ⇒ Socket f → ByteString → μ (Maybe IfIndex)
getIfIndex s name
  | nameLen >= #{const IFNAMSIZ} = return Nothing
  | otherwise = withSocketFd s $ \fd →
      allocaBytesAligned #{size struct ifreq}
                         #{alignment struct ifreq} $ \ptr → do
        void $ BS.memset (castPtr ptr) 0 #{size struct ifreq}
        BS.unsafeUseAsCString name $ \pStr → do
          let namePtr = plusPtr ptr #{offsetof struct ifreq, ifr_name}
          copyBytes namePtr pStr nameLen
        r ← c_ioctl fd #{const SIOCGIFINDEX} ptr
        if r == -1
        then do
          errno ← getErrno
          if errno == eNODEV
          then return Nothing
          else ioError $ errnoToIOError __FILE__ errno Nothing Nothing
        else
          Just . IfIndex <$> #{peek struct ifreq, ifr_ifindex} ptr
  where nameLen = BS.length name

getIfName ∷ MonadBase IO μ ⇒ Socket f → IfIndex → μ (Maybe ByteString)
getIfName s (IfIndex ix) = withSocketFd s $ \fd → do
  allocaBytesAligned #{size struct ifreq}
                     #{alignment struct ifreq} $ \ptr → do
    void $ BS.memset (castPtr ptr) 0 #{size struct ifreq}
    #{poke struct ifreq, ifr_ifindex} ptr ix
    r ← c_ioctl fd #{const SIOCGIFNAME} ptr
    if r == -1
    then do
      errno ← getErrno
      if errno == eNODEV
      then return Nothing
      else ioError $ errnoToIOError __FILE__ errno Nothing Nothing
    else do
      let namePtr = plusPtr ptr #{offsetof struct ifreq, ifr_name}
      Just <$> BS.packCString namePtr

foreign import ccall "ioctl"
  c_ioctl ∷ Fd → CInt → Ptr α → IO CInt

