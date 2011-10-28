{-# LANGUAGE CPP, ForeignFunctionInterface, GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TemplateHaskell #-}

-- | This module provides bindings to /inotify(7)/.
module System.Linux.INotify (
    CreateFlags,
    nonBlockingFlag,
    closeOnExecFlag,

    EventTypes,
    accessedEvent,
    attrChangedEvent,
    closedWEvent,
    closedNWEvent,
    createdEvent,
    childDeletedEvent,
    deletedEvent,
    modifiedEvent,
    movedEvent,
    movedFromEvent,
    movedToEvent,
    openedEvent,
    watchRemovedEvent,
    unmountedEvent,

    AddFlags,
    doNotFollowFlag,
    addEventsFlag,
    oneShotFlag,
    onlyIfDirFlag, 

    Descriptor,
    Event(..),

    create,
    add,
    remove,
    peekEvent,
    readEvents
  ) where

import Data.Word (Word32)
import Data.Bits ((.|.), (.&.), complement)
import Data.Flags.TH (bitmaskWrapper)
import Foreign.Storable (Storable(..))
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.C.Types (CChar)
#if __GLASGOW_HASKELL__ >= 703
import Foreign.C.Types (CInt(..), CSize(..))
#else
import Foreign.C.Types (CInt, CSize)
#endif
import Foreign.C.String (CString, withCString, peekCAString)
import Foreign.C.Error (throwErrnoIf, throwErrnoIfMinus1, throwErrnoIfMinus1_)
import Foreign.Marshal.Alloc (allocaBytes)
import System.Posix.Types (Fd(..))
#if __GLASGOW_HASKELL__ >= 703
import System.Posix.Types (CSsize(..))
#else
import System.Posix.Types (CSsize)
#endif
import Control.Applicative((<$>))

#include <linux/limits.h>
#include <sys/inotify.h>

$(bitmaskWrapper "CreateFlags" ''CInt [''Storable]
    [("nonBlockingFlag", #{const IN_NONBLOCK}),
     ("closeOnExecFlag", #{const IN_CLOEXEC})])

$(bitmaskWrapper "EventTypes" ''Word32 [''Storable]
    [("accessedEvent", #{const IN_ACCESS}),
     ("attrChangedEvent", #{const IN_ATTRIB}),
     ("closedWEvent", #{const IN_CLOSE_WRITE}),
     ("closedNWEvent", #{const IN_CLOSE_NOWRITE}),
     ("createdEvent", #{const IN_CREATE}),
     ("childDeletedEvent", #{const IN_DELETE}),
     ("deletedEvent", #{const IN_DELETE_SELF}),
     ("modifiedEvent", #{const IN_MODIFY}),
     ("movedEvent", #{const IN_MOVE_SELF}),
     ("movedFromEvent", #{const IN_MOVED_FROM}),
     ("movedToEvent", #{const IN_MOVED_TO}),
     ("openedEvent", #{const IN_OPEN}),
     ("watchRemovedEvent", #{const IN_IGNORED}),
     ("unmountedEvent", #{const IN_UNMOUNT})])

$(bitmaskWrapper "AddFlags" ''Word32 [''Storable]
    [("doNotFollowFlag", #{const IN_DONT_FOLLOW}),
     ("addEventsFlag", #{const IN_MASK_ADD}),
     ("oneShotFlag", #{const IN_ONESHOT}),
     ("onlyIfDirFlag", #{const IN_ONLYDIR})])

newtype Descriptor = Descriptor Word32 deriving (Eq, Ord, Show, Storable)

data Event = Event { eventDescriptor :: !Descriptor
                   , eventTypes :: !EventTypes
                   , eventSubjectIsDir :: !Bool
                   , eventCookie :: !Word32
                   , eventName :: !(Maybe FilePath)
                   }
             | OverflowEvent

#let alignment t = "%lu", (unsigned long) offsetof (struct { char x__; t (y__); }, y__)

-- | Create an inotify file descriptor. See /inotify_init1(2)/.
create :: CreateFlags -> IO Fd
create flags =
  throwErrnoIfMinus1 "INotify.create" $ c_inotify_init1 flags

-- | Monitor file or directory for the requested event types.
--   See /inotify_add_watch(2)/.
add :: Fd -> EventTypes -> AddFlags -> FilePath -> IO Descriptor
add fd (EventTypes types) (AddFlags flags) path =
  throwErrnoIf (== Descriptor (-1)) "INotify.add" $
    withCString path $ \p ->
      c_inotify_add_watch fd p (EventTypes $ types .|. flags)

-- | Remove the watch associated with the given descriptor.
--   See /inotify_rm_watch(2)/.
remove :: Fd -> Descriptor -> IO ()
remove fd desc =
  throwErrnoIfMinus1_ "INotify.remove" $ c_inotify_rm_watch fd desc

-- | Try to peek an event from the buffer. On success, return the peeked
--   event and the number of bytes it occupied in the buffer. When the buffer
--   is too small, return the number of bytes that needs to be appended.
peekEvent :: Ptr a -- ^ Buffer to peek an event from.
          -> CSize -- ^ Buffer size.
          -> IO (Either CSize (Event, CSize))
peekEvent p n =
  if n < #{size struct inotify_event}
    then return $ Left $ #{size struct inotify_event} - n
    else do
      desc <- #{peek struct inotify_event, wd} p
      types <- #{peek struct inotify_event, mask} p
      isDir <- return $ types .&. #{const IN_ISDIR} /= 0
      cookie <- #{peek struct inotify_event, cookie} p
      len <- (#{peek struct inotify_event, len} p :: IO Word32)
      if n < #{size struct inotify_event} + fromIntegral len
        then return $ Left $ #{size struct inotify_event} +
                             fromIntegral len - n
        else do
          name <- if len == 0
                    then return Nothing
                    else Just <$> peekCAString
                                    (plusPtr p #{size struct inotify_event})
          return $ Right ((if types == #{const IN_Q_OVERFLOW}
                             then OverflowEvent
                             else Event
                                    desc
                                    (EventTypes $
                                       types .&.
                                       (complement #{const IN_ISDIR}))
                                    isDir cookie name),
                          #{size struct inotify_event} + fromIntegral len)

-- | Read some events (buffer size is
--   @sizeof(struct inotify_event) + NAME_MAX + 1@ rounded up to the
--   nearest multiple of @sizeof(struct inotify_event)@).
readEvents :: Fd -> IO [Event]
readEvents fd = 
    allocaBytes bufSize $ \pBuf -> do
      r <- throwErrnoIf (< #{size struct inotify_event})
                        "INotify.readEvents" $
             c_read fd (castPtr pBuf) $ fromIntegral bufSize
      iter (pBuf :: Ptr CChar) (fromIntegral r) []
  where
    (sizeQuot, sizeRem) =
      (#{const NAME_MAX} + 1) `quotRem` #{size struct inotify_event}
    bufSize = (1 + sizeQuot + signum sizeRem) * #{size struct inotify_event}
    iter p size events = do
      result <- peekEvent p size
      case result of
        Right (e, n) -> iter (plusPtr p $ fromIntegral n) (size - n)
                             (e : events)
        _ -> return $ reverse events
      
foreign import ccall unsafe "inotify_init1"
  c_inotify_init1 :: CreateFlags -> IO Fd
foreign import ccall unsafe "inotify_add_watch"
  c_inotify_add_watch :: Fd -> CString -> EventTypes -> IO Descriptor
foreign import ccall unsafe "inotify_rm_watch"
  c_inotify_rm_watch :: Fd -> Descriptor -> IO CInt

foreign import ccall unsafe "read"
  c_read :: Fd -> Ptr () -> CSize -> IO CSsize

