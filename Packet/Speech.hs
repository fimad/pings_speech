module Packet.Speech (
    Packet (..)
) where

import DH
import CryptoHelper

import Data.Bits
import Data.Word
import Data.LargeWord
import qualified Data.Binary as B
import qualified Data.Binary.Get as BG
import qualified Data.Binary.Put as BP
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as CLBS


--------------------------------------------------------------------------------
-- DataTypes
--------------------------------------------------------------------------------

data Packet = Handshake1
            | Handshake2 {
                authIV :: Word128
              , dhParams :: DHParams Word256
              , serverNonce :: Word32
            }
            | Handshake3 {
                dhShared :: Word256
              , serverNonce :: Word32
              , clientNonce :: Word32
            }
            | Handshake4 {
                dhShared :: Word256
              , sessIV :: Word128
              , clientNonce :: Word32
              , sessionId :: Word32
            }
            | Send {
                sessionId :: Word32
              , sequenceId :: Word64
              , message :: LBS.ByteString
            }
            | Confirm {
                sessionId :: Word32
              , sequenceId :: Word64
            }
            | BadPacket -- used for error catching in parsing packets
  deriving (Show,Eq)

newtype SpeechPacket = SpeechPacket (Word256, Word128, Packet)-- Key, IV, packet

--------------------------------------------------------------------------------
-- Instances
--------------------------------------------------------------------------------

instance (B.Binary a, B.Binary b) => B.Binary (LargeKey a b) where
  put (LargeKey a b) = B.put a >> B.put b
  get = do
    a <- B.get
    b <- B.get
    return $ LargeKey a b


--------------------------------------------------------------------------------
-- Encoding packets
--------------------------------------------------------------------------------

encode :: Key -> IV -> Packet -> (LBS.ByteString,IV)
encode _ iv Handshake1                    =( BP.runPut 
                                           $ B.put (0x4747 :: Word16)
                                          >> B.put (0x01 :: Word8)
                                           , iv )


encode key iv (packet@(Handshake2 _ _ _)) =( BP.runPut
                                           $ B.put (0x4747 :: Word16)
                                          >> B.put (0x02 :: Word8)
                                          >> B.put (authIV packet)
                                          >> B.put enc
                                           , newIv )
  where
    (enc, newIv) = encryptHelper key iv    $ BP.runPut 
                                           $ B.put (getPrime $ dhParams packet)
                                          >> B.put (serverNonce packet)


encode key iv (packet@(Handshake3 _ _ _)) =( BP.runPut
                                           $ B.put (0x4747 :: Word16)
                                          >> B.put (0x03 :: Word8)
                                          >> B.put enc
                                           , newIv )
  where
    (enc, newIv) = encryptHelper key iv    $ BP.runPut 
                                           $ B.put (dhShared packet)
                                          >> B.put (serverNonce packet)
                                          >> B.put (clientNonce packet)


encode key iv (packet@(Handshake4 _ _ _ _))=(BP.runPut
                                           $ B.put (0x4747 :: Word16)
                                          >> B.put (0x04 :: Word8)
                                          >> B.put enc
                                           , newIv )
  where
    (enc, newIv) = encryptHelper key iv    $ BP.runPut 
                                           $ B.put (dhShared packet)
                                          >> B.put (sessIV packet)
                                          >> B.put (clientNonce packet)
                                          >> B.put (sessionId packet)


encode key iv (packet@(Send _ _ _))       =( BP.runPut
                                           $ B.put (0x4747 :: Word16)
                                          >> B.put (0x10 :: Word8)
                                          >> B.put (sessionId packet)
                                          >> B.put (sequenceId packet)
                                          >> B.put enc
                                           , newIv )
  where
    (enc, newIv) = encryptHelper key iv    $ message packet

    
encode key iv (packet@(Confirm _ _))      =( BP.runPut
                                           $ B.put (0x4747 :: Word16)
                                          >> B.put (0x20 :: Word8)
                                          >> B.put (sessionId packet)
                                          >> B.put (sequenceId packet)
                                           , iv )


encode key iv _                           =( BP.runPut
                                           $ B.put (0x00 :: Word8)
                                           , iv )


--------------------------------------------------------------------------------
-- Decoding packets
--------------------------------------------------------------------------------

decode :: Key -> IV -> LBS.ByteString -> (Packet,IV)
decode _ iv _ = (BadPacket,iv)
