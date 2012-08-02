import Data.Char
import Network.Socket
import Data.Binary
import qualified Packet.ICMP as ICMP
import qualified Packet.IP as IP
import qualified Data.ByteString.Lazy.Char8 as LBS

icmpProtocol :: ProtocolNumber
icmpProtocol = 1

main :: IO ()
main = do
  s <- socket AF_INET Raw icmpProtocol
  readLoop s
  return ()

readLoop :: Socket -> IO ()
readLoop socket = do
  (packet,len) <- recvLen socket 0xFFFF
  let ip = decode $ LBS.pack packet
  let icmp = decode $ IP.message ip

  --print $ Prelude.map ord $ packet
  --print $ ipSrc $ decode $ LBS.pack packet
  --print $ Prelude.map ord $ LBS.unpack $ IP.message ip
  print $ ICMP.checksum icmp
  print $ ICMP.checksum $ ICMP.updateChecksum icmp
  putStr "\n"
  readLoop socket

