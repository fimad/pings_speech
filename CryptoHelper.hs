module CryptoHelper (
    Key
  , IV
  , stringToKey
  , encryptHelper
  , decryptHelper
) where

import Codec.Utils
import Codec.Encryption.AES
import Codec.Encryption.Modes
import Codec.Encryption.Padding
import Data.Char
import Data.Word
import Data.LargeWord
import Data.Digest.SHA256
import qualified Data.ByteString.Lazy as LBS

-- | Takes the Sha256 hash of a string to get a usable AES key.
stringToKey :: String -> Word256
stringToKey s = fromTwosComp octetHash
  where
    octetList = listToOctets $ map (fromIntegral . ord :: Char -> Word8) s
    octetHash = hash octetList

type Key = Word256
type IV = Word128

encryptHelper :: Key -> IV -> LBS.ByteString -> (LBS.ByteString,IV)
encryptHelper key iv plainText = (LBS.pack $ listToOctets cipherText, newIv)
  where
    cipherText = cbc encrypt iv key $ listFromOctets $ pkcs5 $ LBS.unpack plainText
    newIv = last cipherText

decryptHelper :: Key -> IV -> LBS.ByteString -> (LBS.ByteString,IV)
decryptHelper key iv cipherText = (LBS.pack $ unPkcs5 $ listToOctets plainText, newIv)
  where
    plainText = unCbc decrypt iv key $ listFromOctets $ LBS.unpack cipherText
    newIv = last $ listFromOctets $ LBS.unpack cipherText
