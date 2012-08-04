module Packet.Speech (
    Packet (..)
) where

import DH
import CryptoHelper

import Data.Bits
import Data.Word
import Data.LargeWord
import Control.Monad
import qualified Data.Binary as B
import qualified Data.Binary.Get as BG
import qualified Data.Binary.Strict.Get as BSG
import qualified Data.Binary.Put as BP
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as CLBS

-- Note: This does not obey network byte order
--       To fix this I think you'd have to add LargeKey as an instance of Data.EndianSensitive


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

getLargeWordS :: (Bits a, Bits b, B.Binary a, B.Binary b) => LargeKey a b -> BSG.Get (LargeKey a b)
getLargeWordS i = do
  bytes <- BSG.getByteString ((bitSize . hiHalf) i + (bitSize . loHalf) i)
  return $ BG.runGet (B.get) (LBS.fromChunks [bytes])


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

-- | Returns either an error message or the result
decode :: Key -> IV -> LBS.ByteString -> (Packet,IV)
decode key iv lazyPacket = 
    case fst $ BSG.runGet getPacket strictPacket of
      Left _       -> (BadPacket,iv)
      Right result -> result
  where
    toStrictBS = BS.concat . LBS.toChunks
    toLazyBS = LBS.fromChunks . (\a -> [a])

    strictPacket = toStrictBS lazyPacket

    eitherToPacket iv (Left _)  = (BadPacket,iv)
    eitherToPacket iv (Right p) = p

    getPacket :: BSG.Get (Packet,IV)
    getPacket = do
      magic <- BSG.getWord16host
      packetType <- BSG.getWord8
      case (magic,packetType) of
          (0x4747, 0x01) -> return $ (Handshake1, iv)

          (0x4747, 0x02) -> do
                              unwrappedBytes <- (BSG.getByteString 128) :: BSG.Get BS.ByteString
                              remaining <- BSG.remaining
                              encryptedBytes <- (BSG.getByteString remaining)
                              let (decryptedBytes, newIv) = (\(d,i) -> (toStrictBS d, i)) $ decryptHelper key iv $ toLazyBS encryptedBytes
                              return $ eitherToPacket iv $ fst $ BSG.runGet (get newIv) (unwrappedBytes `BS.append` decryptedBytes)
                            where
                              get :: IV -> BSG.Get (Packet,IV)
                              get newIv = do
                                iv <- (getLargeWordS 0 :: BSG.Get Word128)
                                prime <- (getLargeWordS 0:: BSG.Get Word256)
                                nonce <- BSG.getWord32host
                                return $ ( Handshake2 {
                                    authIV = iv
                                  , dhParams = paramsFromPrime prime
                                  , serverNonce = nonce
                                }, newIv)

          (0x4747, 0x03) -> do
                              remaining <- BSG.remaining
                              encryptedBytes <- (BSG.getByteString remaining)
                              let (decryptedBytes, newIv) = (\(d,i) -> (toStrictBS d, i)) $ decryptHelper key iv $ toLazyBS encryptedBytes
                              return $ eitherToPacket iv $ fst $ BSG.runGet (get newIv) (decryptedBytes)
                            where
                              get newIv = do
                                shared <- (getLargeWordS 0 :: BSG.Get Word256)
                                snonce <- (BSG.getWord32host)
                                cnonce <- (BSG.getWord32host)
                                return $ ( Handshake3 {
                                    dhShared = shared
                                  , serverNonce = snonce
                                  , clientNonce = cnonce
                                }, newIv)

          (0x4747, 0x04) -> do
                              remaining <- BSG.remaining
                              encryptedBytes <- (BSG.getByteString remaining)
                              let (decryptedBytes, newIv) = (\(d,i) -> (toStrictBS d, i)) $ decryptHelper key iv $ toLazyBS encryptedBytes
                              return $ eitherToPacket iv $ fst $ BSG.runGet (get newIv) (decryptedBytes)
                            where
                              get newIv = do
                                shared <- (getLargeWordS 0 :: BSG.Get Word256)
                                sessIv <- (getLargeWordS 0 :: BSG.Get Word128)
                                cnonce <- (BSG.getWord32host)
                                sess <- (BSG.getWord32host)
                                return $ ( Handshake4 {
                                    dhShared = shared
                                  , sessIV = sessIv
                                  , clientNonce = cnonce
                                  , sessionId = sess
                                }, newIv)

          (0x4747, 0x10) -> do
                              unwrappedBytes <- (BSG.getByteString 96)
                              remaining <- BSG.remaining
                              encryptedBytes <- (BSG.getByteString remaining)
                              let (decryptedBytes, newIv) = (\(d,i) -> (toStrictBS d, i)) $ decryptHelper key iv $ toLazyBS encryptedBytes
                              return $ eitherToPacket iv $ fst $ BSG.runGet (get newIv) (unwrappedBytes `BS.append` decryptedBytes)
                            where
                              get newIv = do
                                sess <- (BSG.getWord32host)
                                seq <- (BSG.getWord64host)
                                remaining <- BSG.remaining
                                msg <- (BSG.getByteString remaining)
                                return $ ( Send {
                                    sessionId = sess
                                  , sequenceId = seq
                                  , message = toLazyBS msg
                                }, newIv)

          (0x4747, 0x20) -> do
                              unwrappedBytes <- (BSG.getByteString 96)
                              return $ eitherToPacket iv $ fst $ BSG.runGet (get iv) (unwrappedBytes)
                            where
                              get newIv = do
                                sess <- (BSG.getWord32host)
                                seq <- (BSG.getWord64host)
                                return $ ( Confirm {
                                    sessionId = sess
                                  , sequenceId = seq
                                }, newIv)

          _              -> return (BadPacket,iv)
        :: BSG.Get (Packet,IV)

