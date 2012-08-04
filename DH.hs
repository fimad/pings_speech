module DH (
    DHParams
  , getPrime
  , getGenerator
  , getSecret -- shouldn't really ever need to see the secret unless debugging
  , getShared
  , genParams
  , genParamsIO
  , paramsFromPrime
  , genSecret
  , genSecretIO
  , genKey
) where

import Prime
import System.Random


data DHParams a = InitialParams a a
                | FinalParams a a a a
  deriving (Show,Eq)

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
genParams :: (RandomGen g, Bounded a, Integral a, Num a) => g -> DHParams a
genParams g = InitialParams 5 (prime g (maxBound))

genParamsIO :: (Bounded a, Integral a, Num a) => IO (DHParams a)
genParamsIO = do
  g <- newStdGen
  return $ genParams g

paramsFromPrime :: (Integral a, Num a) => a -> DHParams a
paramsFromPrime p = InitialParams 5 p

-- | Takes a DHParam returned by genParams and generates the secret integer and the shared value.
genSecret :: (RandomGen g, Bounded a, Integral a, Num a) => g -> a -> DHParams a -> (DHParams a)
genSecret g max params = 
    let
      (a,_) = randomR (2,fromIntegral max) g
    in
      FinalParams
        (getGenerator params)
        (getPrime params)
        (fromIntegral (a :: Integer))
        (fromIntegral $ powMod (fromIntegral $ getPrime params) (fromIntegral $ getGenerator params) a)

genSecretIO :: (Bounded a, Integral a, Num a) => a -> DHParams a -> IO (DHParams a)
genSecretIO max params = do
    g <- newStdGen
    return $ genSecret g max params

-- | Takes a DHParam returned by 'genSecret' and the remote party's shared value and returns the secret key.
genKey :: (Integral a, Num a) => DHParams a -> a -> a
genKey params shared =
    fromIntegral $ powMod
      (fromIntegral $ getPrime params)
      (fromIntegral $ shared)
      (fromIntegral $ getSecret params)
