module Packet.ICMP (
    Type (..)
  , Packet (..)
  , updateChecksum
) where

import Data.Bits
import Data.Word
import Data.Int
import Control.Monad
import qualified Data.Binary as B
import qualified Data.Binary.Get as BG
import qualified Data.ByteString.Lazy.Char8 as CLBS
import qualified Data.ByteString.Lazy as LBS


--------------------------------------------------------------------------------
-- DataTypes
--------------------------------------------------------------------------------

data Type = EchoReply
              | EchoRequest
              | Other Word8
  deriving (Show,Read,Eq)


data Packet = Packet {
      messageType :: Type
    , code :: Word8
    , checksum :: Word16
    , message :: CLBS.ByteString
  } deriving (Show,Read,Eq)


--------------------------------------------------------------------------------
-- Creating Packets
--------------------------------------------------------------------------------

-- updates the checksum
updateChecksum :: Packet -> Packet
updateChecksum packet = packet {checksum = calcSum . LBS.unpack . B.encode $ packet {checksum = 0}}
  where
    calcSum :: [Word8] -> Word16
    calcSum ws = fromIntegral sum'''
      where
        sum = word16Sum ws
        sum' = (shiftR sum 16) + (sum .&. 0xFFFF)
        sum'' = sum' + (shiftR sum' 16)
        sum''' = 0x0000FFFF `xor` (sum'' .&. 0xFFFF)

    word16Sum :: [Word8] -> Int32
    word16Sum [] = 0
    word16Sum [a] = fromIntegral a
    word16Sum (a:b:xs) = ((shiftL (fromIntegral a) 8) .|. (fromIntegral b)) + word16Sum xs

--------------------------------------------------------------------------------
-- Instances
--------------------------------------------------------------------------------

instance B.Binary Type where
  --put :: Type -> Put
  put EchoReply = B.put (0 :: Word8)
  put EchoRequest = B.put (8 :: Word8)
  put (Other i) = B.put (i:: Word8)

  --get :: Get Type
  get = do t <- B.getWord8
           return $ case t of
               0 -> EchoReply
               8 -> EchoRequest
               i -> Other i


instance B.Binary Packet where
  --put :: Packet -> Put
  put packet = B.put (messageType packet)
            >> B.put (code packet)
            >> B.put (checksum packet)
            >> (sequence_ $ map B.put $ LBS.unpack $ message packet)

  --get :: Get Packet
  get = do
      ty <- (B.get :: B.Get Type)
      code <- B.getWord8
      checkSum <- (B.get :: B.Get Word16)
      message <- BG.getRemainingLazyByteString
      return $ Packet {
          messageType = ty
        , code = code
        , checksum = checkSum
        , message = message
      }
