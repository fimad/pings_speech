import Data.Char
import Network.Socket
import Data.Binary
--import qualified Data.Binary.Strict.Get as BSG
----import Data.Endian
--import qualified Data.ByteString.Lazy as LBS
--import qualified Data.ByteString.Lazy.Char8 as CLBS

--import Speech
--import qualified Packet.Speech as Speech
import qualified Packet.ICMP as ICMP
import qualified Packet.IP as IP
import qualified ThreadedBuffer as TB
import Control.Concurrent.MVar
import Control.Concurrent
import System.Posix.Unistd


icmpProtocol :: ProtocolNumber
icmpProtocol = 1

main :: IO ()
main = do
  buffer <- newMVar []
  forkIO (appendBuffer buffer 0)
  readLoop buffer
  where
    readLoop buffer = do
      value <- TB.get buffer
      print value
      threadDelay 100
      readLoop buffer
{-
  s <- socket AF_INET Raw icmpProtocol
  readLoop s
  return ()
  -}

appendBuffer :: MVar [Int] -> Int -> IO ()
appendBuffer buffer current = do
  TB.put buffer [current]
  threadDelay 10
  appendBuffer buffer (current+1)

{-
readLoop :: Socket -> IO ()
readLoop socket = do
  (packet,len) <- recvLen socket 0xFFFF
  let ip = decode $ CLBS.pack packet
  let icmp = decode $ IP.message ip

  --print $ Prelude.map ord $ packet
  --print $ ipSrc $ decode $ CLBS.pack packet
  --print $ Prelude.map ord $ CLBS.unpack $ IP.message ip

  --print $ ICMP.messageType icmp
  --print $ Prelude.map ord $ packet
  --print $ Prelude.map ord $ CLBS.unpack $ encode ip

  let new_icmp = ICMP.updateChecksum $ icmp { ICMP.messageType = ICMP.EchoReply }

  if ICMP.messageType icmp == ICMP.EchoRequest
    then sendTo socket (CLBS.unpack $ encode $ new_icmp) (SockAddrInet aNY_PORT (toBigEndian $ IP.src ip))
    else return 0

  readLoop socket
-}
