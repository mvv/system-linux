{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DoAndIfThenElse #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}

module System.Linux.Netlink.Route (
    rtNlSockProto,

    rtLinkNlGroup,
    rtNotifyNlGroup,
    rtNeighNlGroup,
    rtTcNlGroup,
    rtIfAddr4NlGroup,
    rtMr4NlGroup,
    rtRoute4NlGroup,
    rtRule4NlGroup,
    rtIfAddr6NlGroup,
    rtIfInfo6NlGroup,
    rtMr6NlGroup,
    rtRoute6NlGroup,
    rtRule6NlGroup,
    rtPrefix6NlGroup,

    getRouteNlMsgType,
    newRouteNlMsgType,
    delRouteNlMsgType,

    IfIndex,
    InOrOutIf(..),

    RtFamily(..),
    RtAttr(..),
    inIfRtAttr,
    outIfRtAttr,
    gatewayRtAttr,
    prefSrcRtAttr,
    flowRtAttr,
    markRtAttr,

    RtProto(..),
    unspecRtProto,
    redirRtProto,
    kernelRtProto,
    bootRtProto,
    staticRtProto,

    RtScope(..),
    universeRtScope,
    siteRtScope,
    linkRtScope,
    hostRtScope,
    nowhereRtScope,

    RtType(..),
    unspecRtType,
    localRtType,
    unicastRtType,
    broadcastRtType,
    anycastRtType,
    multicastRtType,
    blackholeRtType,
    unreachableRtType,
    prohibitRtType,
    throwRtType,
    natRtType,
    externalRtType,

    RtFlags(..),
    notifyRtFlag,
    clonedRtFlag,
    eqRtFlag,
    prefixRtFlag,

    RtNlMsg(..),
    getRouteNlMsg,
    decodeRtNlMsg
  ) where

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <system-linux.macros.h>

import Data.Typeable
import Data.Word
import Data.Maybe (isJust, fromJust)
import Data.Ix (Ix)
import Data.Flags
import qualified Data.ByteString as BS
import Data.Serialize
import Data.Default
import Data.IP.Addr
import Control.Applicative ((<$>))
import Control.Monad (when, MonadPlus(mzero), guard)
import System.Posix.Socket
import System.Posix.Socket.Inet (AF_INET)
import System.Linux.Netlink
import System.Linux.Netlink.Internal

rtNlSockProto ∷ SockProto
rtNlSockProto = SockProto #{const NETLINK_ROUTE}

#{enum NlGroup, NlGroup
 , rtLinkNlGroup    = RTNLGRP_LINK
 , rtNotifyNlGroup  = RTNLGRP_NOTIFY
 , rtNeighNlGroup   = RTNLGRP_NEIGH
 , rtTcNlGroup      = RTNLGRP_TC
 , rtIfAddr4NlGroup = RTNLGRP_IPV4_IFADDR
 , rtMr4NlGroup     = RTNLGRP_IPV4_MROUTE
 , rtRoute4NlGroup  = RTNLGRP_IPV4_ROUTE
 , rtRule4NlGroup   = RTNLGRP_IPV4_RULE
 , rtIfAddr6NlGroup = RTNLGRP_IPV6_IFADDR
 , rtIfInfo6NlGroup = RTNLGRP_IPV6_IFINFO
 , rtMr6NlGroup     = RTNLGRP_IPV6_MROUTE
 , rtRoute6NlGroup  = RTNLGRP_IPV6_ROUTE
 , rtRule6NlGroup   = RTNLGRP_IPV6_RULE
 , rtPrefix6NlGroup = RTNLGRP_IPV6_PREFIX
 }

#{enum NlMsgType, NlMsgType
 , getRouteNlMsgType = RTM_GETROUTE
 , newRouteNlMsgType = RTM_NEWROUTE
 , delRouteNlMsgType = RTM_DELROUTE
 }

newtype IfIndex = IfIndex { unIfIndex ∷ Word32 }
                  deriving (Typeable, Eq, Ord, Show)

data InOrOutIf = InIf IfIndex
               | OutIf IfIndex
               deriving (Typeable, Eq, Show)

class (Show f, Default (RtFamilyAddr f), Show (RtFamilyAddr f),
       Show (RtFamilyNetAddr f))
      ⇒ RtFamily f where
  type RtFamilyAddr f
  type RtFamilyNetAddr f
  sizeOfRtAddr      ∷ f → Int
  getRtAddr         ∷ f → Get (RtFamilyAddr f)
  putRtAddr         ∷ f → Putter (RtFamilyAddr f)
  rtFamilyNetAddr   ∷ f → RtFamilyAddr f → Word → RtFamilyNetAddr f
  rtFamilyCode      ∷ f → Word8

instance RtFamily AF_INET where
  type RtFamilyAddr    AF_INET = IP4
  type RtFamilyNetAddr AF_INET = Net4Addr
  sizeOfRtAddr _    = 4
  getRtAddr _       = IP4 <$> getWord32be
  putRtAddr _       = putWord32be . unIP4
  rtFamilyNetAddr _ = mkNetAddr
  rtFamilyCode _    = #const AF_INET

data RtAttr f = InIfRtAttr    IfIndex
              | OutIfRtAttr   IfIndex
              | GatewayRtAttr (RtFamilyAddr f)
              | PrefSrcRtAttr (RtFamilyAddr f)
              | FlowRtAttr    Word32
              | MarkRtAttr    Word32

inIfRtAttr ∷ MonadPlus μ ⇒ RtAttr f → μ IfIndex
inIfRtAttr (InIfRtAttr i) = return i
inIfRtAttr _              = mzero
outIfRtAttr ∷ MonadPlus μ ⇒ RtAttr f → μ IfIndex
outIfRtAttr (OutIfRtAttr i) = return i
outIfRtAttr _               = mzero
gatewayRtAttr ∷ MonadPlus μ ⇒ RtAttr f → μ (RtFamilyAddr f)
gatewayRtAttr (GatewayRtAttr a) = return a
gatewayRtAttr _                 = mzero
prefSrcRtAttr ∷ MonadPlus μ ⇒ RtAttr f → μ (RtFamilyAddr f)
prefSrcRtAttr (PrefSrcRtAttr a) = return a
prefSrcRtAttr _                 = mzero
flowRtAttr ∷ MonadPlus μ ⇒ RtAttr f → μ Word32
flowRtAttr (FlowRtAttr f) = return f
flowRtAttr _              = mzero
markRtAttr ∷ MonadPlus μ ⇒ RtAttr f → μ Word32
markRtAttr (MarkRtAttr m) = return m
markRtAttr _              = mzero

deriving instance Typeable1 RtAttr
deriving instance RtFamily f ⇒ Show (RtAttr f)

newtype RtProto = RtProto Word8
                  deriving (Typeable, Eq, Ord, Bounded, Enum, Ix, Show)

#{enum RtProto, RtProto
 , unspecRtProto = RTPROT_UNSPEC
 , redirRtProto  = RTPROT_REDIRECT
 , kernelRtProto = RTPROT_KERNEL
 , bootRtProto   = RTPROT_BOOT
 , staticRtProto = RTPROT_STATIC
 }

newtype RtScope = RtScope Word8
                  deriving (Typeable, Eq, Ord, Bounded, Enum, Ix, Show)

#{enum RtScope, RtScope
 , universeRtScope = RT_SCOPE_UNIVERSE
 , siteRtScope     = RT_SCOPE_SITE
 , linkRtScope     = RT_SCOPE_LINK
 , hostRtScope     = RT_SCOPE_HOST
 , nowhereRtScope  = RT_SCOPE_NOWHERE
 }

newtype RtType = RtType Word8
                 deriving (Typeable, Eq, Ord, Bounded, Enum, Ix, Show)

#{enum RtType, RtType
 , unspecRtType      = RTN_UNSPEC
 , localRtType       = RTN_LOCAL
 , unicastRtType     = RTN_UNICAST
 , broadcastRtType   = RTN_BROADCAST
 , anycastRtType     = RTN_ANYCAST
 , multicastRtType   = RTN_MULTICAST
 , blackholeRtType   = RTN_BLACKHOLE
 , unreachableRtType = RTN_UNREACHABLE
 , prohibitRtType    = RTN_PROHIBIT
 , throwRtType       = RTN_THROW
 , natRtType         = RTN_NAT
 , externalRtType    = RTN_XRESOLVE
 }

newtype RtFlags = RtFlags Word32
                  deriving (Typeable, Eq, Flags, Show)

#{enum RtFlags, RtFlags
 , notifyRtFlag = RTM_F_NOTIFY
 , clonedRtFlag = RTM_F_CLONED
 , eqRtFlag     = RTM_F_EQUALIZE
 , prefixRtFlag = RTM_F_PREFIX
 }

data RtNlMsg f = RtNlMsg { rtNlMsgNew    ∷ Bool
                         , rtNlMsgSrc    ∷ RtFamilyNetAddr f
                         , rtNlMsgDst    ∷ RtFamilyNetAddr f
                         , rtNlMsgTOS    ∷ Word8
                         , rtNlMsgTable  ∷ Word32
                         , rtNlMsgProto  ∷ RtProto
                         , rtNlMsgScope  ∷ RtScope
                         , rtNlMsgType   ∷ RtType
                         , rtNlMsgFlags  ∷ RtFlags
                         , rtNlMsgAttrs  ∷ [RtAttr f]
                         }

deriving instance Typeable1 RtNlMsg
deriving instance RtFamily f ⇒ Show (RtNlMsg f)

zero ∷ Int → Put
zero n = putByteString $ BS.replicate n 0
{-# INLINE zero #-}

getRouteNlMsg ∷ ∀ f . RtFamily f
              ⇒ f → RtFamilyAddr f → RtFamilyAddr f → Maybe InOrOutIf
              → NlMsg
getRouteNlMsg f src dst iof =
    NlMsg getRouteNlMsgType reqNlMsgFlag bs
  where bs = runPut $ do
          zero #{offsetof struct rtmsg, rtm_family}
          putWord8 $ rtFamilyCode f
          #{zeroAndPut struct rtmsg, rtm_family,   rtm_dst_len}  (0 ∷ Word8)
          #{zeroAndPut struct rtmsg, rtm_dst_len,  rtm_src_len}  (0 ∷ Word8)
          #{zeroAndPut struct rtmsg, rtm_src_len,  rtm_tos}      (0 ∷ Word8)
          #{zeroAndPut struct rtmsg, rtm_tos,      rtm_table}    (0 ∷ Word8)
          #{zeroAndPut struct rtmsg, rtm_table,    rtm_protocol} (0 ∷ Word8)
          #{zeroAndPut struct rtmsg, rtm_protocol, rtm_scope}    (0 ∷ Word8)
          #{zeroAndPut struct rtmsg, rtm_scope,    rtm_type}     (0 ∷ Word8)
          #{zero struct rtmsg, rtm_type, rtm_flags}
          putWord32host 0
          zero $ align4 #{size struct rtmsg} - 4 -
                 #{offsetof struct rtmsg, rtm_flags}
          let addrLen = sizeOfRtAddr f
          let addrAttrLen = align4 #{size struct rtattr} + addrLen
          let putAddr tp addr = do
                zero #{offsetof struct rtattr, rta_len}
                putWord16host $ fromIntegral addrAttrLen
                #{zero struct rtattr, rta_len, rta_type} 
                putWord16host tp
                zero $ align4 #{size struct rtattr} - 2 -
                       #{offsetof struct rtattr, rta_type}
                let addrBs = runPut $ putRtAddr f addr
                putByteString addrBs
                zero $ align4 addrAttrLen - addrAttrLen
          putAddr #{const RTA_SRC} src
          putAddr #{const RTA_DST} dst
          when (isJust iof) $ do
            let (tp, ifix) = case fromJust iof of
                               InIf  i → (#{const RTA_IIF}, i)
                               OutIf i → (#{const RTA_OIF}, i)
            zero #{offsetof struct rtattr, rta_len}
            putWord16host $ align4 #{size struct rtattr} + 4
            #{zero struct rtattr, rta_len, rta_type} 
            putWord16host tp
            zero $ align4 #{size struct rtattr} - 2 -
                   #{offsetof struct rtattr, rta_type}
            putWord32host $ unIfIndex ifix

decodeRtNlMsg ∷ ∀ f . RtFamily f ⇒ f → NlMsg → Maybe (RtNlMsg f)
decodeRtNlMsg f (NlMsg tp _ bs)
  | (tp /= newRouteNlMsgType && tp /= delRouteNlMsgType)
    || BS.length bs < #{size struct rtmsg} = Nothing
  | otherwise = either (const Nothing) Just $ (`runGet` bs) $ do
      uncheckedSkip #{offsetof struct rtmsg, rtm_family}
      guard =<< (== rtFamilyCode f) <$> getWord8
      dstLen ∷ Word8 ← #{skipAndGet struct rtmsg, rtm_family,   rtm_dst_len}
      srcLen ∷ Word8 ← #{skipAndGet struct rtmsg, rtm_dst_len,  rtm_src_len}
      tos    ← #{skipAndGet struct rtmsg, rtm_src_len,  rtm_tos}
      tbl    ← #{skipAndGet struct rtmsg, rtm_tos,      rtm_table}
      proto  ← #{skipAndGet struct rtmsg, rtm_table,    rtm_protocol}
      scope  ← #{skipAndGet struct rtmsg, rtm_protocol, rtm_scope}
      rtType ← #{skipAndGet struct rtmsg, rtm_scope,    rtm_type}
      #{skip struct rtmsg, rtm_type, rtm_flags}
      flags  ← fromIntegral <$> getWord32host
      uncheckedSkip $ #{size struct rtmsg} - 4
                      - #{offsetof struct rtmsg, rtm_flags}
      let getAttrs src dst table attrs = do
            r ← remaining
            if r < #{size struct rtattr}
            then return (src, dst, table, attrs)
            else do
              uncheckedSkip #{offsetof struct rtattr, rta_len}
              totalLen ← fromIntegral <$> getWord16host
              #{skip struct rtattr, rta_len, rta_type}
              attrType ← getWord16host
              uncheckedSkip $ #{size struct rtattr} - 2
                              - #{offsetof struct rtattr, rta_type}
              if totalLen < #{size struct rtattr} || r < totalLen
              then return (src, dst, table, attrs)
              else do
                let attrLen = totalLen - align4 #{size struct rtattr}
                    getAddr = do
                      guard $ attrLen == sizeOfRtAddr f
                      isolate attrLen $ do
                        addr ← getRtAddr f
                        uncheckedSkip =<< remaining
                        return addr
                    cont src' dst' table' attrs' = do
                      if r <= align4 totalLen
                      then return (src', dst', table', attrs')
                      else do
                        uncheckedSkip $ align4 totalLen - totalLen
                        getAttrs src' dst' table' attrs'
                case attrType of
                  t | t == #{const RTA_DST} → do
                    dst' ← getAddr
                    cont src dst' table attrs
                  t | t == #{const RTA_SRC} → do
                    src' ← getAddr
                    cont src' dst table attrs
                  t | t == #{const RTA_TABLE} → do
                    guard $ attrLen == 4
                    table' ← getWord32host
                    cont src dst table' attrs
                  t | t == #{const RTA_GATEWAY} → do
                    gw ← getAddr
                    cont src dst table (GatewayRtAttr gw : attrs)
                  t | t == #{const RTA_PREFSRC} → do
                    prefSrc ← getAddr
                    cont src dst table (PrefSrcRtAttr prefSrc : attrs)
                  t | t == #{const RTA_IIF} → do
                    guard $ attrLen == 4
                    ifix ← IfIndex <$> getWord32host
                    cont src dst table (InIfRtAttr ifix : attrs)
                  t | t == #{const RTA_OIF} → do
                    guard $ attrLen == 4
                    ifix ← IfIndex <$> getWord32host
                    cont src dst table (OutIfRtAttr ifix : attrs)
                  t | t == #{const RTA_FLOW} → do
                    guard $ attrLen == 4
                    flow ← getWord32host
                    cont src dst table (FlowRtAttr flow : attrs)
                  _ → do
                    uncheckedSkip attrLen
                    cont src dst table attrs
      (src, dst, table, attrs) ← do
        r ← remaining
        let pad = align4 #{size struct rtmsg} - #{size struct rtmsg}
        if r <= pad
        then return (def, def, fromIntegral (tbl ∷ Word8), [])
        else do
          uncheckedSkip pad
          (src, dst, table, attrs) ←
            getAttrs def def (fromIntegral (tbl ∷ Word8)) []
          return (src, dst, table, reverse attrs)
      let mkNet = rtFamilyNetAddr f
      return $ RtNlMsg { rtNlMsgNew   = tp == newRouteNlMsgType
                       , rtNlMsgSrc   = mkNet src (fromIntegral srcLen)
                       , rtNlMsgDst   = mkNet dst (fromIntegral dstLen)
                       , rtNlMsgTOS   = tos
                       , rtNlMsgTable = table
                       , rtNlMsgProto = RtProto proto
                       , rtNlMsgScope = RtScope scope
                       , rtNlMsgType  = RtType rtType
                       , rtNlMsgFlags = RtFlags flags
                       , rtNlMsgAttrs = attrs
                       }
decodeRtNlMsg _ _ = Nothing

