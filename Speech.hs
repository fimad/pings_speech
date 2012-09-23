module Speech (
    SpeechState
  , Options
  , ConnectionState
  , handlePacket

  -- | API
  , SpeechSessionHandle
  , connectToServer
  , startSingleUserServer
  , writeSpeech
  , readSpeech
) where

import DH
import CryptoHelper
import qualified Packet.IP as IP
import qualified Packet.ICMP as ICMP
import qualified Packet.Speech as SPCH
import qualified ThreadedBuffer as TB

import Data.Word
import Data.Binary
import Data.LargeWord
import System.Clock
import System.Random
import Control.Monad
import Control.Concurrent
import Control.Concurrent.MVar
import qualified Network.Socket as S
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as CLBS
import qualified Data.Heap as Heap
import qualified Data.Map as Map



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
    , inputBuffer :: MVar [LBS.ByteString] -- | Messages that need to be sent out
    , outputBuffer :: MVar [LBS.ByteString] -- | Messages that have been recieved
    , isActive :: MVar Bool
    , sendQueue :: Heap.Heap (Heap.Entry TimeSpec (SPCH.Packet,Bool)) -- (when to send, (packet, needs confirmation?))
  } --deriving (Show,Eq)

data ConnectionState = SentHandshake1
                     | SentHandshake2 (DHParams Word256) Nonce
                     | SentHandshake3 (DHParams Word256) Nonce
                     | Established Sequence Sequence -- myCurrentSequence theirCurrentSequence
                     | Closed
  deriving (Show,Eq)

type SpeechState = (ConnectionState,Options)

-- The library client has a handle to the input and output buffers
type SpeechSessionHandle = (MVar Bool, MVar [LBS.ByteString], MVar [LBS.ByteString]) -- (active,input,output)


--------------------------------------------------------------------------------
-- Speech IO API
--------------------------------------------------------------------------------

-- | Reads all the recieved speech messages from the buffer
readSpeech :: SpeechSessionHandle -> IO [LBS.ByteString]
readSpeech (_,_,output) = TB.get output 

-- | Writes a list of messages to the input buffer of a speech session
-- | It is more efficient to make one call with many messages, than many calls with single messages
writeSpeech :: SpeechSessionHandle -> [LBS.ByteString] -> IO ()
writeSpeech (_,input,_) messages = TB.put input messages

--------------------------------------------------------------------------------
-- Speech Utilities
--------------------------------------------------------------------------------

-- | Creates a new handle to a speech session
newHandle :: IO SpeechSessionHandle
newHandle = do
  active <- newMVar True
  input <- newMVar []
  output <- newMVar []
  return (active,input,output)

-- | Creates a handle for a specific speech state
handleFromState :: SpeechState -> SpeechSessionHandle
handleFromState (state,options) = (isActive options, inputBuffer options, outputBuffer options)

-- | Provides "sane" defaults for options, hopefull each will get a real value before being used.
defaultOptions :: IO Options
defaultOptions = do
  ib <- newMVar []
  ob <- newMVar []
  active <- newMVar True
  return $ Options {
      icmpType = ICMP.EchoReply
    , otherIp = 0
    , sessionId = 0
    , sessionKey = 0
    , txIv = 0
    , rxIv = 0
    , inputBuffer = ib
    , outputBuffer = ob
    , isActive = active
    , sendQueue = Heap.empty
  }

queuePacket :: Bool -> SPCH.Packet -> SpeechState -> IO SpeechState
queuePacket confirm packet (state,options) = do
  currentTime <- getTime Monotonic
  let newQueue = Heap.insert (Heap.Entry currentTime (packet,confirm)) (sendQueue options)
  return (state, options {sendQueue = newQueue})

queueReliablePacket :: SPCH.Packet -> SpeechState -> IO SpeechState
queueReliablePacket = queuePacket True

queueUnreliablePacket :: SPCH.Packet -> SpeechState -> IO SpeechState
queueUnreliablePacket = queuePacket False

dequeuePacket :: Sequence -> SpeechState -> IO SpeechState
dequeuePacket sequence (state,options) = do
  let queue = sendQueue options
  let newQueue = Heap.filter (not . isSendAndSeq sequence . fst . Heap.payload) queue
  return (state, options {sendQueue = newQueue})

  where
    isSendAndSeq seq packet@(SPCH.Send _ _ _) = seq == (SPCH.sequenceId packet)
    isSendAndSeq _ _ = False

--------------------------------------------------------------------------------
-- Generic Speech Worker Thread
--------------------------------------------------------------------------------

-- | Takes a map of existing sessions to MVar lists of packets.
-- | Will spawn new sessions if appropriate
--packetShufflerThread :: Map.Map IO ()
--packetShufflerThread  

-- TODO Just realized that this isn't going to work for multiple simultaneous sessions 
--   if one thread grabs the packet that another needs the other won't ever read that packet
--   there needs to be another thread that just shuffles packets in and out
--   associates each with a sessionId and provies a mechanism for grabbing packets by sessionId
--   It can also be responsible for spawninga new thread for each session
speechThread :: SpeechState -> IO ()
speechThread (state,options) = S.withSocketsDo $ do
  socket <- S.socket S.AF_INET S.Raw 1 -- 1 is the icmpProtocol 
  threadLoop (state,options) socket
  where
    threadLoop (state,options) socket = do
      --write inputBuffer to the packet queue
      (state',options') <- case state of
        Established mySeq theirSeq -> do
          -- send the buffered messages
          messages <- TB.get $ inputBuffer options
          foldM queueMessagePacket (state,options) messages
        otherwise ->
          -- don't try to send messages until we are established
          return (state,options)

      --handle packets off socket
      --TODO IMPLEMENT ME!
      --TODO FIGURE OUT POLLING
      --(packet,len) <- S.recvLen socket 0xFFFF
      (packet,len,addr) <- S.recvFrom socket 0xFFFF --hopefully this is nonblocking?
      let ip = decode $ CLBS.pack packet
      let icmp = decode $ IP.message ip :: ICMP.Packet

      --process the packet queue and write to socket
      --TODO IMPLEMENT ME!

      yield -- play nice and share the cpu
      --TODO should terminate when the we are no longer active
      threadLoop (state',options') socket

    --foldable function for queueing a send packet for a message
    queueMessagePacket (Established mySeq theirSeq, options) message = do
      let packet = SPCH.Send {
          SPCH.sessionId = sessionId options
        , SPCH.sequenceId = mySeq
        , SPCH.message = message
      }
      queueReliablePacket packet ((Established (mySeq+1) theirSeq), options)

    --recieves and handles packets until there are no more to handle
    receiveAndHandlePackets (state,options) socket = do
      (packet,len,addr) <- S.recvFrom socket 0xFFFF --hopefully this is nonblocking?
      let ip = decode $ CLBS.pack packet
      let icmp = decode $ IP.message ip
      let (speech,txIv') = SPCH.decode (sessionKey options) (txIv options) $ ICMP.message icmp
      gen <- newStdGen
      case (speech, otherIp options, addr) of
        (SPCH.BadPacket,_,_) -> return (state, options) -- it was a bad packet, ignore that shit
        --update the ip address if we don't currently have one
        --also determine if we should be sending echo requests or replys
        (SPCH.Handshake1,0,S.SockAddrInet _ ip) ->
          handlePacket gen speech (state, options {
                otherIp = ip
              , icmpType = ICMP.flipType $ ICMP.messageType icmp
            })
        (SPCH.Handshake1,_,_) -> return (state, options) -- this is wierd, maybe ipv6?, ignore it
        (packet,_,_) ->
          if sessionId options == SPCH.sessionId packet -- make sure it's relevant to the session
            then return (state, options)
            else return (state, options)


--------------------------------------------------------------------------------
-- Speech Client
--------------------------------------------------------------------------------

-- | Connects to a server, spawns a worker thread to handle networking and returns the handle
connectToServer :: IP.IpAddress -> IO SpeechSessionHandle
connectToServer ip = do
  options <- defaultOptions  >>= (\o -> return o{
        otherIp = ip
      , icmpType = ICMP.EchoRequest
    })
  let state = (SentHandshake1, options) 
  let handle = handleFromState state
  state' <- queueUnreliablePacket SPCH.Handshake1 state -- queue the first handshake packet
  forkIO $ speechThread state -- spawn worker bee
  return handle


--------------------------------------------------------------------------------
-- Speech Server
--------------------------------------------------------------------------------
 
-- -T-O-D-O- The server needs to figure out what the other IP is at some point
--      Seems like it should be handled by the handlePacket functon but it is not privy to the ip
--      I think this is taken care of now, the function that passes packets to this update the ip
--      if it encounteres a handshake1 when there was no ip set
-- | Stars a server that only handles a single connection at a time.
startSingleUserServer :: IO SpeechSessionHandle
startSingleUserServer = do
  options <- defaultOptions >>= (\o -> return o{
        icmpType = ICMP.EchoReply
    })
  let state = (Closed, options)
  let handle = handleFromState state
  forkIO $ speechThread state -- spawn worker bee
  return handle

--------------------------------------------------------------------------------
-- Handle Packets
--------------------------------------------------------------------------------

-- | Takes a packet and a state and returns a list of packets that should be sent in response and the new connection state
handlePacket :: (RandomGen g) => g -> SPCH.Packet -> SpeechState -> IO SpeechState
handlePacket g SPCH.Handshake1 (Closed,options) =
    queueUnreliablePacket
      (SPCH.Handshake2 {
          SPCH.sessionId = sess
        , SPCH.authIV = iv
        , SPCH.dhParams = params
        , SPCH.serverNonce = nonce
      })
      (SentHandshake2 params nonce, options {txIv = iv, rxIv = iv})
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
    queueUnreliablePacket
      SPCH.Handshake3 {
          SPCH.sessionId = sess
        , SPCH.dhShared = getShared newParams
        , SPCH.serverNonce = sNonce
        , SPCH.clientNonce = cNonce
      }
      (SentHandshake3 newParams cNonce, options {txIv = iv, rxIv = iv})
  where
    (g',g'') = split g
    newParams = genSecret g' maxBound params
    cNonce = fromIntegral $ fst $ randomR (0::Integer, fromIntegral $ (maxBound :: Word32)) g''


handlePacket g (SPCH.Handshake3 sess shared sNonce_recv cNonce) (SentHandshake2 params sNonce_sent,options) =
    -- make sure the nonce's match
    if sNonce_recv == sNonce_sent
    then
      queueUnreliablePacket
        SPCH.Handshake4 {
            SPCH.sessionId = sess
          , SPCH.dhShared = getShared params
          , SPCH.sessIV = iv
          , SPCH.clientNonce = cNonce
        }
        (Established 0 0, options {txIv = iv, rxIv = iv, sessionKey = key})
    else
      return (Closed,options) -- close the connection
  where
    (g',g'') = split g
    newParams = genSecret g' maxBound params
    iv = fromIntegral $ fst $ randomR (0::Integer, fromIntegral $ (maxBound :: IV)) g''
    key = genKey params shared


handlePacket g (SPCH.Handshake4 sess shared iv cNonce_recv) (SentHandshake3 params cNonce_sent,options) =
    -- make sure the nonce's match
    if cNonce_recv == cNonce_sent
    then
      -- connection established, no need to send any packets
      return (Established 0 0, options {txIv = iv, rxIv = iv, sessionKey = key})
    else
      return (Closed,options) -- close the connection
  where
    key = genKey params shared


-- TODO some how return the contents of msg
handlePacket g (SPCH.Send sess seq msg) state@(Established _ _,_) =
        queueReliablePacket (SPCH.Confirm sess seq) state


-- TODO add a queue and then update it
handlePacket g (SPCH.Confirm sess seq) state@(Established _ _,_) =
      dequeuePacket seq state


-- TODO determine better generic cases for handlPacket
-- Not sure it's best to close the connection, could lead to DOS vulnerabilities
-- might be better to just ignore them
handlePacket _ _ (_,options) = return (Closed,options {otherIp = 0}) -- close the connection if anything else happens

