module Speech (
    SpeechState
  , SpeechSession
) where

import Data.Word
import qualified Packet.ICMP as ICMP

data SpeechState = Handshake1 
                 | Handshake2
                 | Handshake3 
                 | Handshake4 
                 | ConnectedAsServer 
                 | ConnectedAsClient 
                 | Closed
  deriving (Show,Read,Eq)

data SpeechSession = SpeechSession {
      icmpType :: ICMP.Type
    , state :: SpeechState
    , otherIP :: Word32
    , sessionId :: Word32
  } deriving (Show,Read,Eq)
