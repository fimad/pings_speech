module Speech (
    SpeechState
  , Options
  , ConnectionState
  , handlePacket
) where

import DH
import CryptoHelper
import qualified Packet.IP as IP
import qualified Packet.ICMP as ICMP
import qualified Packet.Speech as SPCH

import Data.Word
import Data.LargeWord
import System.Random


type Session  = Word32
type Sequence = Word64
type Nonce    = Word32

-- | Session options that persist between various connection States
data Options = Options {
      icmpType :: ICMP.Type -- | do we send reply's or requests?
    , otherIp :: IP.IpAddress -- | Who are we talking to?
    , sessionId :: Session
    , sessionKey :: Key
    , txIv :: IV -- | the IV for encrypting/transmitting packets
    , rxIv :: IV -- | the IV for decrypting/receiving packets
  } deriving (Show,Eq)

data ConnectionState = SentHandshake1
                     | SentHandshake2 (DHParams Word256) Nonce
                     | SentHandshake3 (DHParams Word256) Nonce
                     | Established Sequence Sequence -- myCurrentSequence theirCurrentSequence
                     | Closed
  deriving (Show,Eq)

-- TODO add the packet queue to the state so that handlePacket can remove packets that have been confirmed
-- TODO we also need a way to get message out of the state..... 
type SpeechState = (ConnectionState,Options)
 

--------------------------------------------------------------------------------
-- Handle Packets
--------------------------------------------------------------------------------

-- | Takes a packet and a state and returns a list of packets that should be sent in response and the new connection state
handlePacket :: (RandomGen g) => g -> SPCH.Packet -> SpeechState -> ([SPCH.Packet],SpeechState)
handlePacket g SPCH.Handshake1 (Closed,options) =
    ([
      SPCH.Handshake2 {
          SPCH.sessionId = sess
        , SPCH.authIV = iv
        , SPCH.dhParams = params
        , SPCH.serverNonce = nonce
      }
    ],
      (SentHandshake2 params nonce, options {txIv = iv, rxIv = iv})
    )
  where
    (g',g'') = split g
    (g''',g'''') = split g'
    sess = fromIntegral $ fst $ randomR (0::Integer, fromIntegral $ (maxBound :: Word32)) g
    --hacky way to generate random large words
    iv = fromIntegral $ fst $ randomR (0::Integer, fromIntegral $ (maxBound :: IV)) g'
    params = genSecret g''' maxBound (genParams g'')
    nonce = fromIntegral $ fst $ randomR (0::Integer, fromIntegral $ (maxBound :: Word32)) g'''


-- TODO
-- IV's are weird here because we need to know it to decode the packet but it won't be set until we process this packet
handlePacket g (SPCH.Handshake2 sess iv params sNonce) (SentHandshake1,options) =
    ([
      SPCH.Handshake3 {
          SPCH.sessionId = sess
        , SPCH.dhShared = getShared newParams
        , SPCH.serverNonce = sNonce
        , SPCH.clientNonce = cNonce
      }
    ],
      (SentHandshake3 newParams cNonce, options {txIv = iv, rxIv = iv})
    )
  where
    (g',g'') = split g
    newParams = genSecret g' maxBound params
    cNonce = fromIntegral $ fst $ randomR (0::Integer, fromIntegral $ (maxBound :: Word32)) g''


handlePacket g (SPCH.Handshake3 sess shared sNonce_recv cNonce) (SentHandshake2 params sNonce_sent,options) =
    -- make sure the nonce's match
    if sNonce_recv == sNonce_sent
    then
      ([
        SPCH.Handshake4 {
            SPCH.sessionId = sess
          , SPCH.dhShared = getShared params
          , SPCH.sessIV = iv
          , SPCH.clientNonce = cNonce
        }
      ],
        (Established 0 0, options {txIv = iv, rxIv = iv, sessionKey = key})
      )
    else
      ([],(Closed,options)) -- close the connection
  where
    (g',g'') = split g
    newParams = genSecret g' maxBound params
    iv = fromIntegral $ fst $ randomR (0::Integer, fromIntegral $ (maxBound :: IV)) g''
    key = genKey params shared


handlePacket g (SPCH.Handshake4 sess shared iv cNonce_recv) (SentHandshake3 params cNonce_sent,options) =
    -- make sure the nonce's match
    if cNonce_recv == cNonce_sent
    then
      ([], -- connection established, no need to send any packets
        (Established 0 0, options {txIv = iv, rxIv = iv, sessionKey = key})
      )
    else
      ([],(Closed,options)) -- close the connection
  where
    key = genKey params shared


-- TODO some how return the contents of msg
handlePacket g (SPCH.Send sess seq msg) state@(Established _ _,_) =
      (
        [SPCH.Confirm sess seq]
      ,
        state
      )


-- TODO add a queue and then update it
handlePacket g (SPCH.Confirm sess seq) state@(Established _ _,_) =
      (
        []
      ,
        state
      )


-- Not sure it's best to close the connection, could lead to DOS vulnerabilities
-- might be better to just ignore them
handlePacket _ _ (_,options) = ([],(Closed,options)) -- close the connection if anything else happens

