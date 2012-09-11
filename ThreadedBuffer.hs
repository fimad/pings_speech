module ThreadedBuffer (
    get
  , put
) where
import Data.Monoid
import Control.Concurrent.MVar

get :: (Monoid a) => MVar a -> IO a
get bufferMVar = modifyMVar bufferMVar (\buffer -> return (mempty,buffer))
put :: (Monoid a) => MVar a -> a-> IO ()
put bufferMVar value = modifyMVar_ bufferMVar (\buffer -> return (buffer `mappend` value))
