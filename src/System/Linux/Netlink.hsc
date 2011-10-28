{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}

module System.Linux.Netlink (
    NlGroup(..),
    noNlGroup,
    NlAddr(..),
    autoNlAddr,
    kernelNlAddr,
    AF_NETLINK(..),
    NETLINK_ADD_MEMBERSHIP(..),
    NETLINK_DROP_MEMBERSHIP(..),
    NETLINK_PKTINFO(..),
    NlMsgType(..),
    noOpNlMsgType,
    errorNlMsgType,
    doneNlMsgType,
    overrunNlMsgType,
    customNlMsgType,
    NlMsgFlags(..),
    reqNlMsgFlag,
    multiNlMsgFlag,
    ackNlMsgFlag,
    echoNlMsgFlag,
    rootNlMsgFlag,
    matchNlMsgFlag,
    atomicNlMsgFlag,
    dumpNlMsgFlag,
    replaceNlMsgFlag,
    exclNlMsgFlag,
    createNlMsgFlag,
    appendNlMsgFlag,
    NlSeq,
    NlMsg(..),
    NlError(..),
    nlSocket,
    nlAddGroup,
    nlAddGroups,
    nlDropGroup,
    nlDropGroups,
    nlRecv,
    nlSend
  ) where

import Data.Typeable (Typeable)
import Data.Word
import Data.Flags
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Control.Applicative ((<$>), (<*>))
import Control.Monad (void, forM_)
import Control.Monad.Base
import Control.Exception
import Foreign.C.Types (CInt)
#if __GLASGOW_HASKELL__ >= 703
import Foreign.C.Types (CSize(..))
#else
import Foreign.C.Types (CSize)
#endif
import Foreign.C.Error (Errno(..))
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (Storable(..))
import Foreign.Marshal.Alloc (allocaBytesAligned)
import System.Posix.Types (CPid)
import System.Posix.Socket
import System.Linux.Netlink.Internal

#include <sys/socket.h>
#include <linux/netlink.h>
#include <system-linux.macros.h>

#ifndef SOL_NETLINK
# define SOL_NETLINK 270
#endif

newtype NlGroup = NlGroup { unNlGroup ∷ CInt } deriving (Eq, Show)

noNlGroup ∷ NlGroup
noNlGroup = NlGroup 0

-- | Netlink address.
data NlAddr = NlAddr { nlAddrPid   ∷ CPid
                     , nlAddrGroup ∷ NlGroup
                     } deriving (Eq, Show)

autoNlAddr, kernelNlAddr ∷ NlAddr
autoNlAddr   = NlAddr 0 noNlGroup
kernelNlAddr = NlAddr 0 noNlGroup

instance SockAddr NlAddr where
  sockAddrMaxSize _ = #{size struct sockaddr_nl}
  sockAddrSize    _ = #{size struct sockaddr_nl}
  peekSockAddr local p sz =
    if sz /= #{size struct sockaddr_nl}
      then ioError $ userError $
             "peekSockAddr(NlAddr): invalid size (got " ++ show sz ++
             ", expected " ++ show (#{size struct sockaddr_nl} ∷ Int) ++ ")"
      else NlAddr <$> #{peek struct sockaddr_nl, nl_pid} p
                  <*> if local then return noNlGroup
                      else NlGroup <$> #{peek struct sockaddr_nl, nl_groups} p
  pokeSockAddr local p (NlAddr pid (NlGroup grp)) = do
    #{poke struct sockaddr_nl, nl_pid} p pid
    #{poke struct sockaddr_nl, nl_groups} p (if local then 0 else grp)

data AF_NETLINK = AF_NETLINK deriving (Typeable, Eq, Show)

instance SockFamily AF_NETLINK where
  type SockFamilyAddr AF_NETLINK = NlAddr
  sockFamilyCode _ = #const AF_NETLINK

data NETLINK_ADD_MEMBERSHIP = NETLINK_ADD_MEMBERSHIP
                              deriving (Typeable, Eq, Show)

instance SockOpt NETLINK_ADD_MEMBERSHIP where
  type SockOptValue    NETLINK_ADD_MEMBERSHIP = NlGroup
  type SockOptRaw      NETLINK_ADD_MEMBERSHIP = CInt
  type SockOptReadable NETLINK_ADD_MEMBERSHIP = ()
  type SockOptWritable NETLINK_ADD_MEMBERSHIP = NETLINK_ADD_MEMBERSHIP
  sockOptRaw _   = unNlGroup
  sockOptValue _ = NlGroup
  sockOptLevel _ = #const SOL_NETLINK
  sockOptCode _  = #const NETLINK_ADD_MEMBERSHIP

data NETLINK_DROP_MEMBERSHIP = NETLINK_DROP_MEMBERSHIP
                               deriving (Typeable, Eq, Show)

instance SockOpt NETLINK_DROP_MEMBERSHIP where
  type SockOptValue    NETLINK_DROP_MEMBERSHIP = NlGroup
  type SockOptRaw      NETLINK_DROP_MEMBERSHIP = CInt
  type SockOptReadable NETLINK_DROP_MEMBERSHIP = ()
  type SockOptWritable NETLINK_DROP_MEMBERSHIP = NETLINK_DROP_MEMBERSHIP
  sockOptRaw _   = unNlGroup
  sockOptValue _ = NlGroup
  sockOptLevel _ = #const SOL_NETLINK
  sockOptCode _  = #const NETLINK_DROP_MEMBERSHIP

data NETLINK_PKTINFO = NETLINK_PKTINFO
                       deriving (Typeable, Eq, Show)

instance SockOpt NETLINK_PKTINFO where
  type SockOptValue    NETLINK_PKTINFO = Bool
  type SockOptRaw      NETLINK_PKTINFO = CInt
  type SockOptReadable NETLINK_PKTINFO = NETLINK_PKTINFO
  type SockOptWritable NETLINK_PKTINFO = NETLINK_PKTINFO
  sockOptRaw _ False = 0
  sockOptRaw _ True  = 1
  sockOptValue _ = (/= 0)
  sockOptLevel _ = #const SOL_NETLINK
  sockOptCode  _ = #const NETLINK_PKTINFO

newtype NlMsgType = NlMsgType Word16
                    deriving (Typeable, Eq, Ord, Bounded, Enum, Show, Storable)

#{enum NlMsgType, NlMsgType
 , noOpNlMsgType    = NLMSG_NOOP
 , errorNlMsgType   = NLMSG_ERROR
 , doneNlMsgType    = NLMSG_DONE
 , overrunNlMsgType = NLMSG_OVERRUN
 , customNlMsgType  = NLMSG_MIN_TYPE
 }

newtype NlMsgFlags = NlMsgFlags Word16
                     deriving (Typeable, Eq, Show, Flags, Storable)

#{enum NlMsgFlags, NlMsgFlags
 , reqNlMsgFlag     = NLM_F_REQUEST
 , multiNlMsgFlag   = NLM_F_MULTI
 , ackNlMsgFlag     = NLM_F_ACK
 , echoNlMsgFlag    = NLM_F_ECHO
 , rootNlMsgFlag    = NLM_F_ROOT
 , matchNlMsgFlag   = NLM_F_MATCH
 , atomicNlMsgFlag  = NLM_F_ATOMIC
 , replaceNlMsgFlag = NLM_F_REPLACE
 , exclNlMsgFlag    = NLM_F_EXCL
 , createNlMsgFlag  = NLM_F_CREATE
 , appendNlMsgFlag  = NLM_F_APPEND
 }

dumpNlMsgFlag ∷ NlMsgFlags
dumpNlMsgFlag = rootNlMsgFlag .+. matchNlMsgFlag

type NlSeq = Word32

data NlMsg = NoOpNlMsg
           | DoneNlMsg
           | ErrorNlMsg Errno NlSeq
           | NlMsg NlMsgType NlMsgFlags ByteString
           deriving (Typeable, Eq)

instance Show NlMsg where
  show NoOpNlMsg    = "NoOpNlMsg"
  show DoneNlMsg    = "DoneNlMsg"
  show (ErrorNlMsg (Errno e) sq) = "ErrnoNlMsg (Errno " ++ show e ++ ") " ++
                                   show sq 
  show (NlMsg tp flags bs) = "NlMsg " ++ show tp ++ " " ++ show flags ++
                             " " ++ show bs

data NlError = FormatNlError
             | OverrunNlError
             deriving (Typeable, Eq, Show)

instance Exception NlError

nlSocket ∷ MonadBase μ IO ⇒ SockProto → μ (Socket AF_NETLINK)
nlSocket sp = liftBase $ do
  s ← socket AF_NETLINK datagramSockType sp
  bind s autoNlAddr `onException` close s
  return s

nlAddGroup ∷ MonadBase μ IO ⇒ Socket AF_NETLINK → NlGroup → μ ()
nlAddGroup s = setSockOpt s NETLINK_ADD_MEMBERSHIP

nlAddGroups ∷ MonadBase μ IO ⇒ Socket AF_NETLINK → [NlGroup] → μ ()
nlAddGroups s grps = forM_ grps $ nlAddGroup s

nlDropGroup ∷ MonadBase μ IO ⇒ Socket AF_NETLINK → NlGroup → μ ()
nlDropGroup s = setSockOpt s NETLINK_DROP_MEMBERSHIP

nlDropGroups ∷ MonadBase μ IO ⇒ Socket AF_NETLINK → [NlGroup] → μ ()
nlDropGroups s grps = forM_ grps $ nlDropGroup s

nlMsgDataOff ∷ Int
nlMsgDataOff = align4 #{size struct nlmsghdr}
{-# INLINE nlMsgDataOff #-}

nlRecv ∷ MonadBase μ IO
       ⇒ Socket AF_NETLINK → μ ([(NlMsg, NlSeq)], Maybe NlError)
nlRecv s = liftBase $
  allocaBytesAligned 8192 #{alignment struct nlmsghdr} $ \p → do
    (r, flags) ← recvBuf s p 8192 noFlags
    let go off msgs ovr
          | off > r - #{size struct nlmsghdr} =
              return (reverse msgs, if ovr then Just OverrunNlError
                                           else Nothing)
          | otherwise = do
              let pHdr = plusPtr p off
              len ← fromIntegral <$>
                      (#{peek struct nlmsghdr, nlmsg_len} pHdr ∷ IO Word32)
              if len < #{size struct nlmsghdr}
                then return (reverse msgs, Just $ if ovr then OverrunNlError
                                                         else FormatNlError)
                else do
                  tp  ← #{peek struct nlmsghdr, nlmsg_type} pHdr
                  sq  ← #{peek struct nlmsghdr, nlmsg_seq}  pHdr
                  msg ← case tp of
                    t | t == noOpNlMsgType → return $ Just NoOpNlMsg
                    t | t == doneNlMsgType → return $ Just DoneNlMsg
                    t | t == errorNlMsgType →
                      if len < nlMsgDataOff + #{size struct nlmsgerr}
                        then return Nothing
                        else do
                          let pData = plusPtr pHdr nlMsgDataOff
                          e   ← #{peek struct nlmsgerr, error} pData
                          let pEHdr = #{ptr struct nlmsgerr, msg} pData
                          esq ← #{peek struct nlmsghdr, nlmsg_seq} pEHdr
                          return $ Just $ ErrorNlMsg (Errno e) esq
                    _ → do
                      nlFlags ← #{peek struct nlmsghdr, nlmsg_flags} pHdr
                      let pData   = plusPtr pHdr nlMsgDataOff
                          dataLen = len - nlMsgDataOff
                      bs ← if dataLen <= 0
                             then return BS.empty
                             else BS.create dataLen $ \pBS →
                                    void $ c_memcpy pBS pData
                                             (fromIntegral dataLen)
                      return $ Just $ NlMsg tp nlFlags bs
                  go (off + align4 len)
                     (maybe msgs (\m → (m, sq) : msgs) msg)
                     ovr
    if r < #{size struct nlmsghdr}
      then return ([], Just FormatNlError)
      else go 0 [] (flags .>=. truncMsgFlag)

nlSend ∷ MonadBase μ IO ⇒ Socket AF_NETLINK → NlMsg → NlSeq → μ ()
nlSend s msg sq = liftBase $
  allocaBytesAligned nlMsgDataOff #{alignment struct nlmsghdr} $ \pHdr → do
    let len = case msg of
                ErrorNlMsg _ _  → nlMsgDataOff + #{size struct nlmsgerr}
                NlMsg _ _ bs    → nlMsgDataOff + BS.length bs
                _               → #{size struct nlmsghdr}
    #{poke struct nlmsghdr, nlmsg_len} pHdr (fromIntegral len ∷ Word32)
    #{poke struct nlmsghdr, nlmsg_seq} pHdr sq
    #{poke struct nlmsghdr, nlmsg_pid} pHdr (0 ∷ CPid)
    let cont bufs =
          void $ sendBufs s ((pHdr, min len nlMsgDataOff) : bufs) noFlags
    case msg of
      NoOpNlMsg → do
        #{poke struct nlmsghdr, nlmsg_type}  pHdr noOpNlMsgType
        #{poke struct nlmsghdr, nlmsg_flags} pHdr (0 ∷ Word16)
        cont []
      DoneNlMsg → do
        #{poke struct nlmsghdr, nlmsg_type}  pHdr doneNlMsgType
        #{poke struct nlmsghdr, nlmsg_flags} pHdr (0 ∷ Word16)
        cont []
      ErrorNlMsg (Errno e) esq → do
        #{poke struct nlmsghdr, nlmsg_type}  pHdr errorNlMsgType
        #{poke struct nlmsghdr, nlmsg_flags} pHdr (0 ∷ Word16)
        allocaBytesAligned #{size struct nlmsgerr}
                           #{alignment struct nlmsgerr} $ \pData → do
          #{poke struct nlmsgerr, error} pData e
          let pEHdr = #{ptr struct nlmsgerr, msg} pData
          #{poke struct nlmsghdr, nlmsg_len}   pEHdr
            (#{size struct nlmsghdr} ∷ Word32)
          #{poke struct nlmsghdr, nlmsg_type}  pEHdr noOpNlMsgType
          #{poke struct nlmsghdr, nlmsg_flags} pEHdr (0 ∷ Word16)
          #{poke struct nlmsghdr, nlmsg_seq}   pEHdr esq
          #{poke struct nlmsghdr, nlmsg_pid}   pEHdr (0 ∷ CPid)
          cont [(pData, #{size struct nlmsgerr})]
      NlMsg tp (NlMsgFlags flags) bs → do
        #{poke struct nlmsghdr, nlmsg_type}  pHdr tp
        #{poke struct nlmsghdr, nlmsg_flags} pHdr flags
        BS.unsafeUseAsCStringLen bs $ \(pData, dataLen) →
          cont [(castPtr pData, dataLen)]

foreign import ccall "memcpy"
  c_memcpy ∷ Ptr α → Ptr β → CSize → IO (Ptr α)

