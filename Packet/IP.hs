module Packet.IP (
    Packet (..)
  , updateChecksum
  , IpAddress
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

type IpAddress = Word32

data Packet = Packet {
      version :: Word8
    , headerLen :: Word8
    , dscp :: Word8
    , ecn :: Word8
    , length :: Word16
    , id :: Word16
    , flags :: Word16
    , fragment :: Word16
    , ttl :: Word8
    , protocol :: Word8
    , checksum :: Word16
    , src :: IpAddress
    , dst :: IpAddress
    , message :: CLBS.ByteString
  } deriving (Show,Read,Eq)


--------------------------------------------------------------------------------
-- Creating Packets
--------------------------------------------------------------------------------

-- updates the checksum
updateChecksum :: Packet -> Packet
updateChecksum packet = packet {checksum = calcSum . LBS.unpack . B.encode $ packet {checksum = 0, message = LBS.empty}}
  where
    calcSum :: [Word8] -> Word16
    calcSum ws = fromIntegral sum
      where
        sum = (2 + word16Sum ws) `xor` 0xFFFF

    word16Sum :: [Word8] -> Word16
    word16Sum [] = 0
    word16Sum (a:b:xs) = ((shiftL (fromIntegral a) 8) .|. (fromIntegral b)) + word16Sum xs


--------------------------------------------------------------------------------
-- Instances
--------------------------------------------------------------------------------

instance B.Binary Packet where
  put packet = B.put ((shiftL (version packet) 4) .|. (headerLen packet))
            >> B.put ((shiftL (dscp packet) 2) .|. (ecn packet))
            >> B.put (Packet.IP.length packet)
            >> B.put (Packet.IP.id packet)
            >> B.put ((shiftL (flags packet) 13) .|. (fragment packet))
            >> B.put (ttl packet)
            >> B.put (protocol packet)
            >> B.put (checksum packet)
            >> B.put (src packet)
            >> B.put (dst packet)
            >> (sequence_ $ map B.put $ LBS.unpack $ message packet)

  get = do
      version_headerLen <- B.getWord8
      dscp_ecn <- B.getWord8
      length <- (B.get :: B.Get Word16)
      id <- (B.get :: B.Get Word16)
      flags_fragment <- (B.get :: B.Get Word16)
      ttl <- B.getWord8
      protocol <- B.getWord8
      checksum <- (B.get :: B.Get Word16)
      src <- (B.get :: B.Get Word32)
      dst <- (B.get :: B.Get Word32)
      message <- BG.getRemainingLazyByteString
      return $ Packet {
          version = (shiftR version_headerLen 4) .&. 0x0F
        , headerLen = version_headerLen .&. 0x0F
        , dscp = (shiftR dscp_ecn 2) .&. 0x3F
        , ecn = dscp_ecn .&. 0x03
        , Packet.IP.length = length
        , Packet.IP.id = id
        , flags = (shiftR flags_fragment 13) .&. 0x0007
        , fragment = flags_fragment .&. 0x3FFF
        , ttl = ttl
        , protocol = protocol
        , checksum = checksum
        , src = src
        , dst = dst
        , message = message
      }
