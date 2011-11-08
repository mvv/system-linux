{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts #-}

-- | This module provides bindings to /signalfd(2)/.
module System.Linux.SignalFd (
    CreateFlags,
    nonBlockingFlag,
    closeOnExecFlag,

    Event(..),
    eventSignal,

    create,
    modify,
    readEvent
  ) where

import Data.Word (Word64)
import Data.Flags (noFlags)
import Data.Flags.TH (bitmaskWrapper, enumADT)
import Control.Applicative ((<$>), (<*>))
import Control.Monad.Base
import Control.Concurrent (threadWaitRead)
import Foreign.Storable (Storable(..))
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (Ptr, WordPtr, castPtr)
#if __GLASGOW_HASKELL__ >= 703
import Foreign.C.Types (CInt(..), CSize(..))
#else
import Foreign.C.Types (CInt, CSize)
#endif
import Foreign.C.Error (eBADF, errnoToIOError, throwErrnoIf_,
                        throwErrnoIfMinus1, throwErrnoIfMinus1_)
import Foreign.Marshal.Alloc (alloca)
import System.Posix.Types (Fd(..), ProcessID, UserID, ClockTick)
#if __GLASGOW_HASKELL__ >= 703
import System.Posix.Types (CSsize(..))
#else
import System.Posix.Types (CSsize)
#endif
import System.Posix.Signals
import System.Posix.Timer (Timer)
import System.Posix.Process (ProcessStatus)
import System.Posix.Process.Internals (decipherWaitStatus)
import Unsafe.Coerce (unsafeCoerce)

#include <sys/signalfd.h>
#include <signal.h>

$(bitmaskWrapper "CreateFlags" ''CInt [''Storable]
    [("nonBlockingFlag", #{const SFD_NONBLOCK}),
     ("closeOnExecFlag", #{const SFD_CLOEXEC})])

$(enumADT "SigIllCode" ''CInt
    [("SigIllOpCode",       #{const ILL_ILLOPC}),
     ("SigIllOperand",      #{const ILL_ILLOPN}),
     ("SigIllAddrMode",     #{const ILL_ILLADR}),
     ("SigIllTrap",         #{const ILL_ILLTRP}),
     ("SigIllPrivOpCode",   #{const ILL_PRVOPC}),
     ("SigIllPrivRegister", #{const ILL_PRVREG}),
     ("SigIllCoProcessor",  #{const ILL_COPROC}),
     ("SigIllStack",        #{const ILL_BADSTK})])

$(enumADT "SigFpeCode" ''CInt
    [("SigFpeIntDivByZero",       #{const FPE_INTDIV}),
     ("SigFpeIntOverflow",        #{const FPE_INTOVF}),
     ("SigFpeFloatDivByZero",     #{const FPE_FLTDIV}),
     ("SigFpeFloatOverflow",      #{const FPE_FLTOVF}),
     ("SigFpeFloatUnderflow",     #{const FPE_FLTUND}),
     ("SigFpeFloatInexactResult", #{const FPE_FLTRES}),
     ("SigFpeFloatInvOperation",  #{const FPE_FLTINV}),
     ("SigFpeFloatSubscript",     #{const FPE_FLTSUB})])

$(enumADT "SigSegvCode" ''CInt
    [("SigSegvMap",  #{const SEGV_MAPERR}),
     ("SigSegvPerm", #{const SEGV_ACCERR})])

$(enumADT "SigBusCode" ''CInt
    [("SigBusAlign",  #{const BUS_ADRALN}),
     ("SigBusAddr",   #{const BUS_ADRERR}),
     ("SigBusObject", #{const BUS_OBJERR})])

$(enumADT "SigTrapCode" ''CInt
    [("SigTrapBreakpoint", #{const TRAP_BRKPT}),
     ("SigTrapTrace",      #{const TRAP_TRACE})])

$(enumADT "SigChldCode" ''CInt
    [("SigChldExited",    #{const CLD_EXITED}),
     ("SigChldKilled",    #{const CLD_KILLED}),
     ("SigChldDumped",    #{const CLD_DUMPED}),
     ("SigChldTrapped",   #{const CLD_TRAPPED}),
     ("SigChldStopped",   #{const CLD_STOPPED}),
     ("SigChldContinued", #{const CLD_CONTINUED})])

$(enumADT "SigPollCode" ''CInt
    [("SigPollIn",       #{const POLL_IN}),
     ("SigPollOut",      #{const POLL_OUT}),
     ("SigPollMsg",      #{const POLL_MSG}),
     ("SigPollError",    #{const POLL_ERR}),
     ("SigPollUrgentIn", #{const POLL_PRI}),
     ("SigPollHup",      #{const POLL_HUP})])

data Event = SigIllEvent { sigIllCode ∷ SigIllCode
                         , sigIllAddr ∷ WordPtr
                         }
           | SigFpeEvent { sigFpeCode ∷ SigFpeCode
                         , sigFpeAddr ∷ WordPtr
                         }
           | SigSegvEvent { sigSegvCode ∷ SigSegvCode
                          , sigSegvAddr ∷ WordPtr
                          }
           | SigBusEvent { sigBusCode ∷ SigBusCode
                         , sigBusAddr ∷ WordPtr
                         }
           | SigTrapEvent { sigTrapCode ∷ SigTrapCode
                          , sigTrapAddr ∷ WordPtr
                          }
           | SigChldEvent { sigChldCode     ∷ SigChldCode
                          , sigChldUid      ∷ UserID
                          , sigChldPid      ∷ ProcessID
                          , sigChldStatus   ∷ ProcessStatus
                          , sigChldUserTime ∷ ClockTick
                          , sigChldSysTime  ∷ ClockTick
                          }
           | SigPollEvent { sigPollCode ∷ SigPollCode
                          , sigPollFd   ∷ Fd
                          , sigPollBand ∷ CInt
                          }
           | UserEvent { userEvSignal ∷ Signal
                       , userEvUid    ∷ UserID
                       , userEvPid    ∷ ProcessID
                       }
           | KernelEvent { kernelEvSignal ∷ Signal }
           | QueuedEvent { queuedEvSignal   ∷ Signal
                         , queuedEvUserData ∷ WordPtr
                         , queuedEvUid      ∷ UserID
                         , queuedEvPid      ∷ ProcessID
                         }
           | TimerEvent { timerEvSignal   ∷ Signal
                        , timerEvTimer    ∷ Timer
                        , timerEvOverrun  ∷ CInt
                        , timerEvUserData ∷ WordPtr
                        }
           | MsgQueueEvent { msgQueueEvSignal   ∷ Signal
                           , msgQueueEvUserData ∷ WordPtr
                           }
           | AsyncIOEvent !Signal
           | IOEvent !Signal
           | ThreadEvent !Signal
           deriving (Eq, Show)

eventSignal ∷ Event → Signal
eventSignal (SigIllEvent _ _)          = sigILL
eventSignal (SigFpeEvent _ _)          = sigFPE
eventSignal (SigSegvEvent _ _)         = sigSEGV
eventSignal (SigBusEvent _ _)          = sigBUS
eventSignal (SigTrapEvent _ _)         = sigTRAP
eventSignal (SigChldEvent _ _ _ _ _ _) = sigCHLD
eventSignal (SigPollEvent _ _ _)       = sigPOLL
eventSignal (UserEvent signal _ _)     = signal
eventSignal (KernelEvent signal)       = signal
eventSignal (QueuedEvent signal _ _ _) = signal
eventSignal (TimerEvent signal _ _ _)  = signal
eventSignal (MsgQueueEvent signal _)   = signal
eventSignal (AsyncIOEvent signal)      = signal
eventSignal (IOEvent signal)           = signal
eventSignal (ThreadEvent signal)       = signal

#let alignment t = "%lu", (unsigned long) offsetof (struct { char x__; t (y__); }, y__)

instance Storable Event where
  alignment _ = #{alignment struct signalfd_siginfo}
  sizeOf _ = #{size struct signalfd_siginfo}
  peek p = do
    signal ← #{peek struct signalfd_siginfo, ssi_signo} p
    code   ← #{peek struct signalfd_siginfo, ssi_code} p ∷ IO CInt
    case code of
      #{const SI_USER} →
        UserEvent signal <$> #{peek struct signalfd_siginfo, ssi_uid} p
                         <*> #{peek struct signalfd_siginfo, ssi_pid} p
      #{const SI_KERNEL} → return $ KernelEvent signal
      #{const SI_QUEUE} →
        QueuedEvent signal <$> #{peek struct signalfd_siginfo, ssi_ptr} p
                           <*> #{peek struct signalfd_siginfo, ssi_uid} p
                           <*> #{peek struct signalfd_siginfo, ssi_pid} p
      #{const SI_TIMER} →
        TimerEvent signal <$> #{peek struct signalfd_siginfo, ssi_tid} p
                          <*> #{peek struct signalfd_siginfo, ssi_overrun} p
                          <*> #{peek struct signalfd_siginfo, ssi_ptr} p
      #{const SI_MESGQ} →
        MsgQueueEvent signal <$> #{peek struct signalfd_siginfo, ssi_ptr} p
      #{const SI_ASYNCIO} → return $ AsyncIOEvent signal
      #{const SI_SIGIO} → return $ IOEvent signal
      #{const SI_TKILL} → return $ ThreadEvent signal
      _ →
        case signal of
          #{const SIGILL} → do
            SigIllEvent
              <$> #{peek struct signalfd_siginfo, ssi_code} p
              <*> (fromIntegral <$>
                     (#{peek struct signalfd_siginfo, ssi_addr} p ∷ IO Word64))
          #{const SIGFPE} →
            SigFpeEvent
              <$> #{peek struct signalfd_siginfo, ssi_code} p
              <*> (fromIntegral <$>
                     (#{peek struct signalfd_siginfo, ssi_addr} p ∷ IO Word64))
          #{const SIGSEGV} →
            SigSegvEvent
              <$> #{peek struct signalfd_siginfo, ssi_code} p
              <*> (fromIntegral <$>
                     (#{peek struct signalfd_siginfo, ssi_addr} p ∷ IO Word64))
          #{const SIGBUS} →
            SigBusEvent
              <$> #{peek struct signalfd_siginfo, ssi_code} p
              <*> (fromIntegral <$>
                     (#{peek struct signalfd_siginfo, ssi_addr} p ∷ IO Word64))
          #{const SIGTRAP} →
            SigTrapEvent
              <$> #{peek struct signalfd_siginfo, ssi_code} p
              <*> (fromIntegral <$>
                     (#{peek struct signalfd_siginfo, ssi_addr} p ∷ IO Word64))
          #{const SIGCHLD} →
            SigChldEvent
              <$> #{peek struct signalfd_siginfo, ssi_code} p
              <*> #{peek struct signalfd_siginfo, ssi_uid} p
              <*> #{peek struct signalfd_siginfo, ssi_pid} p
              <*> (decipherWaitStatus =<<
                     #{peek struct signalfd_siginfo, ssi_status} p)
              <*> #{peek struct signalfd_siginfo, ssi_utime} p
              <*> #{peek struct signalfd_siginfo, ssi_stime} p
          #{const SIGPOLL} →
            SigPollEvent
              <$> #{peek struct signalfd_siginfo, ssi_code} p
              <*> #{peek struct signalfd_siginfo, ssi_fd} p
              <*> #{peek struct signalfd_siginfo, ssi_band} p
          _ →
            UserEvent signal <$> #{peek struct signalfd_siginfo, ssi_uid} p
                             <*> #{peek struct signalfd_siginfo, ssi_pid} p
  poke p event = do
    #{poke struct signalfd_siginfo, ssi_signo} p $ eventSignal event
    case event of
      SigIllEvent code addr → do
        #{poke struct signalfd_siginfo, ssi_code} p code
        #{poke struct signalfd_siginfo, ssi_addr} p
          (fromIntegral addr ∷ Word64)
      SigFpeEvent code addr → do
        #{poke struct signalfd_siginfo, ssi_code} p code
        #{poke struct signalfd_siginfo, ssi_addr} p
          (fromIntegral addr ∷ Word64)
      SigSegvEvent code addr → do
        #{poke struct signalfd_siginfo, ssi_code} p code
        #{poke struct signalfd_siginfo, ssi_addr} p
          (fromIntegral addr ∷ Word64)
      SigBusEvent code addr → do
        #{poke struct signalfd_siginfo, ssi_code} p code
        #{poke struct signalfd_siginfo, ssi_addr} p
          (fromIntegral addr ∷ Word64)
      SigTrapEvent code addr → do
        #{poke struct signalfd_siginfo, ssi_code} p code
        #{poke struct signalfd_siginfo, ssi_addr} p
          (fromIntegral addr ∷ Word64)
      SigChldEvent code uid pid status utime stime → do
        #{poke struct signalfd_siginfo, ssi_code} p code
        #{poke struct signalfd_siginfo, ssi_uid} p uid
        #{poke struct signalfd_siginfo, ssi_pid} p pid
        -- FIXME: #{poke struct signalfd_siginfo, ssi_status} p status
        #{poke struct signalfd_siginfo, ssi_utime} p utime
        #{poke struct signalfd_siginfo, ssi_stime} p stime
      SigPollEvent code fd band → do
        #{poke struct signalfd_siginfo, ssi_code} p code
        #{poke struct signalfd_siginfo, ssi_fd} p fd
        #{poke struct signalfd_siginfo, ssi_band} p band
      UserEvent _ uid pid → do
        #{poke struct signalfd_siginfo, ssi_uid} p uid
        #{poke struct signalfd_siginfo, ssi_pid} p pid
      QueuedEvent _ ud uid pid → do
        #{poke struct signalfd_siginfo, ssi_ptr} p ud
        #{poke struct signalfd_siginfo, ssi_uid} p uid
        #{poke struct signalfd_siginfo, ssi_pid} p pid
      TimerEvent _ timer overruns ud → do
        #{poke struct signalfd_siginfo, ssi_tid} p timer
        #{poke struct signalfd_siginfo, ssi_overrun} p overruns
        #{poke struct signalfd_siginfo, ssi_ptr} p ud
      MsgQueueEvent _ ud →
        #{poke struct signalfd_siginfo, ssi_ptr} p ud
      _ → return ()
      
-- | Create a signalfd file descriptor for the requested set of signals.
--   See /signalfd(2)/.
create ∷ MonadBase IO μ ⇒ CreateFlags → SignalSet → μ Fd
create flags sigmask =
  liftBase $ throwErrnoIfMinus1 "SignalFd.create" $
    withForeignPtr (unsafeCoerce sigmask) $ \p →
      c_signalfd (-1) p flags

-- | Change the associated set of signals. See /signalfd(2)/.
modify ∷ MonadBase IO μ ⇒ Fd → SignalSet → μ ()
modify fd sigmask = liftBase $
  if fd == Fd (-1)
    then ioError $ errnoToIOError "SignalFd.modify" eBADF Nothing Nothing
    else throwErrnoIfMinus1_ "SignalFd.modify" $
           withForeignPtr (unsafeCoerce sigmask) $ \p →
             c_signalfd fd p noFlags

-- | Read an event.
readEvent ∷ MonadBase IO μ ⇒ Fd → μ Event
readEvent fd = liftBase $ do
    threadWaitRead fd
    alloca $ \p → do
      throwErrnoIf_ (/= (fromIntegral eventSize)) "SignalFd.readEvent" $
        c_read fd (castPtr p) $ fromIntegral eventSize
      peek p
  where eventSize = sizeOf (undefined ∷ Event)

foreign import ccall unsafe "signalfd"
  c_signalfd ∷ Fd → Ptr α → CreateFlags → IO Fd

foreign import ccall "read"
  c_read ∷ Fd → Ptr α → CSize → IO CSsize

