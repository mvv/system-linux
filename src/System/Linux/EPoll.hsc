{-# LANGUAGE CPP, ForeignFunctionInterface, TemplateHaskell #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- | This module provides bindings to /epoll(7)/.
module System.Linux.EPoll (
    CreateFlags,
    closeOnExecFlag,

    EventTypes,
    inEvent,
    outEvent,
    peerHangupEvent,
    urgentInEvent,
    errorEvent,
    hangupEvent,

    AddFlags,
    edgeTriggeredFlag,
    oneShotFlag,

    Event(..),

    create,
    add,
    modify,
    remove,
    waitSingle,
    waitSingleT,
    wait,
  ) where

import Data.Word (Word32)
import Data.Bits ((.|.))
import Data.Flags ()
import Data.Flags.TH (bitmaskWrapper)
import Foreign.Storable (Storable(..))
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (Ptr, nullPtr)
import Foreign.C.Types (CInt)
import Foreign.C.Error (errnoToIOError, eINVAL, throwErrnoIf_,
                        throwErrnoIfMinus1, throwErrnoIfMinus1_)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (with)
import System.Posix.Types (Fd(..))
import System.Posix.Signals (SignalSet)
import Unsafe.Coerce (unsafeCoerce)
import Control.Applicative ((<$>), (<*>))

#include <sys/epoll.h>

$(bitmaskWrapper "CreateFlags" ''CInt [''Storable]
    [("closeOnExecFlag", #{const EPOLL_CLOEXEC})])

$(bitmaskWrapper "EventTypes" ''Word32 [''Storable]
    [("inEvent", #{const EPOLLIN}),
     ("outEvent", #{const EPOLLOUT}),
     ("peerHangupEvent", #{const EPOLLRDHUP}),
     ("urgentInEvent", #{const EPOLLPRI}),
     ("errorEvent", #{const EPOLLERR}),
     ("hangupEvent", #{const EPOLLHUP})])

$(bitmaskWrapper "AddFlags" ''Word32 [''Storable]
    [("edgeTriggeredFlag", #{const EPOLLET}),
     ("oneShotFlag", #{const EPOLLONESHOT})])

data Event = Event { eventFd :: Fd, eventTypes :: EventTypes }
               deriving (Eq, Show)

#let alignment t = "%lu", (unsigned long) offsetof (struct { char x__; t (y__); }, y__)

instance Storable Event where
  alignment _ = #{alignment struct epoll_event}
  sizeOf _ = #{size struct epoll_event}
  peek p =
    Event <$> peekByteOff p (#{offset struct epoll_event, data}
                             + #{offset union epoll_data, fd})
          <*> #{peek struct epoll_event, events} p
  poke p (Event fd events) = do
    pokeByteOff p (#{offset struct epoll_event, data}
                   + #{offset union epoll_data, fd}) fd
    #{poke struct epoll_event, events} p events

-- | Create an epoll file descriptor. See /epoll_create1(2)/.
create :: CreateFlags -> IO Fd
create flags = throwErrnoIfMinus1 "EPoll.create" $ c_epoll_create1 flags

-- | Register the file descriptor to the epoll instance. See /epoll_ctl(2)/.
add :: Fd -- ^ Epoll file descriptor.
    -> EventTypes
    -> AddFlags
    -> Fd -- ^ File descriptor to register.
    -> IO ()
add efd (EventTypes types) (AddFlags flags) fd =
  throwErrnoIfMinus1_ "EPoll.add" $
    with (Event fd $ EventTypes $ types .|. flags) $
      c_epoll_ctl efd (#const EPOLL_CTL_ADD) fd

-- | Alter parameters of the file descriptor that is already registered to
--   epoll.  See /epoll_ctl(2)/.
modify :: Fd -- ^ Epoll file descriptor.
       -> EventTypes
       -> AddFlags
       -> Fd -- ^ File descriptor to modify.
       -> IO ()
modify efd (EventTypes types) (AddFlags flags) fd =
  throwErrnoIfMinus1_ "EPoll.modify" $
    with (Event fd $ EventTypes $ types .|. flags) $
      c_epoll_ctl efd (#const EPOLL_CTL_MOD) fd

-- | Deregister the file descriptor from epoll. See /epoll_ctl(2)/.
remove :: Fd -- ^ Epoll file descriptor.
       -> Fd -- ^ File descriptor to deregister.
       -> IO ()
remove efd fd =
  throwErrnoIfMinus1_ "EPoll.remove" $
    c_epoll_ctl efd (#const EPOLL_CTL_DEL) fd nullPtr

-- | Wait for an event. See /epoll_[p]wait(2)/.
waitSingle :: Fd -- ^ Epoll file descriptor.
           -> Maybe SignalSet -- ^ Optional signal mask to set.
           -> IO Event
waitSingle efd maybeSigmask = 
  alloca $ \p -> do
    throwErrnoIf_ (/= 1) "EPoll.waitSingle" $
      wait efd p 1 maybeSigmask Nothing
    peek p

-- | Wait for an event for at most the specified amount of time.
--   See /epoll_[p]wait(2)/.
waitSingleT :: Fd -- ^ Epoll file descriptor.
            -> Maybe SignalSet -- ^ Optional signal mask to set.
            -> CInt -- ^ Timeout in milliseconds.
            -> IO (Maybe Event)
waitSingleT efd maybeSigmask timeout =
  alloca $ \p -> do
    cnt <- wait efd p 1 maybeSigmask (Just timeout)
    if cnt == 0
      then return Nothing
      else Just <$> peek p
  
-- | Wait for events. See /epoll_[p]wait(2)/.
wait :: Fd -- ^ Epoll file descriptor.
     -> Ptr Event -- ^ Pointer to events.
     -> CInt -- ^ Maximum number of events to read.
     -> Maybe SignalSet -- ^ Optional signal mask to set.
     -> Maybe CInt -- ^ Optional timeout in milliseconds.
     -> IO CInt
wait efd p maxEvents maybeSigmask maybeTimeout = do
  timeout <- case maybeTimeout of
               Just timeout ->
                 if timeout < 0
                   then ioError $ errnoToIOError "EPoll.wait"
                                                 eINVAL Nothing Nothing
                   else return timeout
               Nothing -> return (-1)
  throwErrnoIfMinus1 "EPoll.wait" $
    case maybeSigmask of
      Just sigmask ->
        withForeignPtr (unsafeCoerce sigmask)
                       (c_epoll_pwait efd p maxEvents timeout)
      Nothing ->
        c_epoll_wait efd p maxEvents timeout
 
foreign import ccall unsafe "epoll_create1"
  c_epoll_create1 :: CreateFlags -> IO Fd
foreign import ccall unsafe "epoll_ctl"
  c_epoll_ctl :: Fd -> CInt -> Fd -> Ptr Event -> IO CInt
foreign import ccall unsafe "epoll_wait"
  c_epoll_wait :: Fd -> Ptr Event -> CInt -> CInt -> IO CInt
foreign import ccall unsafe "epoll_pwait"
  c_epoll_pwait :: Fd -> Ptr Event -> CInt -> CInt -> Ptr () -> IO CInt

