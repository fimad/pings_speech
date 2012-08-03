module DH (
    DHParams
  , getPrime
  , getGenerator
  , getSecret -- shouldn't really ever need to see the secret unless debugging
  , getShared
  , genParams
  , genSecret
  , genKey
) where

import Prime
import System.Random

data DHParams a = InitialParams a a
                | FinalParams a a a a

getPrime :: DHParams a -> a
getPrime (InitialParams _ p) = p
getPrime (FinalParams _ p _ _) = p

getGenerator :: DHParams a -> a
getGenerator (InitialParams g _) = g
getGenerator (FinalParams g _ _ _) = g

-- | Only defined for DHParams that have been returned from 'genSecret'!!
getSecret :: DHParams a -> a
getSecret (FinalParams _ _ s _) = s

-- | Only defined for DHParams that have been returned from 'genSecret'!!
getShared :: DHParams a -> a
getShared (FinalParams _ _ _ s) = s

-- | Initialize a diffie-hellman session, generates a prime and a generator.
genParams :: (Bounded a, Integral a, Num a) => IO (DHParams a)
genParams = do
  p <- prime (maxBound)
  return $ InitialParams 5 p -- always use 5 as the generator, because why not

-- | Takes a DHParam returned by genParams and generates the secret integer and the shared value.
genSecret :: (Bounded a, Integral a, Num a) => a -> DHParams a -> IO (DHParams a)
genSecret max params = do
    g <- newStdGen
    let (a,_) = randomR (2,fromIntegral max) g :: (Integer, StdGen)
    return $ FinalParams
      (getGenerator params)
      (getPrime params)
      (fromIntegral a)
      (fromIntegral $ powMod (fromIntegral $ getPrime params) (fromIntegral $ getGenerator params) a)

-- | Takes a DHParam returned by 'genSecret' and the remote party's shared value and returns the secret key.
genKey :: (Integral a, Num a) => DHParams a -> a -> IO a
genKey params shared = do
    return $ fromIntegral $ powMod
      (fromIntegral $ getPrime params)
      (fromIntegral $ shared)
      (fromIntegral $ getSecret params)
