module Packet.Speech (
    MessageType (..)
  , Packet (..)
  , magicNumber
) where

import Data.Bits
import Data.Word
import qualified Data.Binary as B
import qualified Data.Binary.Get as BG
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as CLBS


--------------------------------------------------------------------------------
-- DataTypes
--------------------------------------------------------------------------------

data MessageType = Handshake1 
                 | Handshake2 
                 | Handshake3 
                 | Handshake4 
                 | Send
                 | Confirm
                 | Close
  deriving (Show,Read,Eq)

data Packet = Packet {
      magic :: Word16
    , isServer :: Bool
    , messageType :: MessageType
    , sessionId :: Word32
    , sequenceId :: Word64
    , message :: LBS.ByteString
  } deriving (Show,Read,Eq)

magicNumber :: Word16
magicNumber = 0x4747


--------------------------------------------------------------------------------
-- Instances
--------------------------------------------------------------------------------

putType :: MessageType -> Word8
putType Handshake1 = (0 :: Word8)
putType Handshake2 = (1 :: Word8)
putType Handshake3 = (2 :: Word8)
putType Handshake4 = (3 :: Word8)
putType Send       = (4 :: Word8)
putType Confirm    = (5 :: Word8)
putType Close      = (6 :: Word8)

getType :: Word8 -> MessageType
getType t = case t of
         0 -> Handshake1
         1 -> Handshake2
         2 -> Handshake3
         3 -> Handshake4
         4 -> Send
         5 -> Confirm
         _ -> Close


instance B.Binary Packet where
  put packet = B.put (magic packet)
            >> B.put ((if isServer packet then 0x80 else 0x00) .|. (putType . messageType) packet)
            >> B.put (sessionId packet)
            >> B.put (sequenceId packet)
            >> (sequence_ $ map B.put $ LBS.unpack $ message packet)

  get = do
      magic <- (B.get :: B.Get Word16)
      server_type <- B.getWord8
      sess <- (B.get :: B.Get Word32)
      seq <- (B.get :: B.Get Word64)
      message <- BG.getRemainingLazyByteString
      return $ Packet {
          magic = magic
        , isServer = server_type .&. 0x80 == 0x80
        , messageType = getType $ server_type .&. 0x7F
        , sessionId = sess
        , sequenceId = seq
        , message = message
      }
