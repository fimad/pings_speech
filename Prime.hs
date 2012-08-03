module Prime (
    prime
  , mulMod
  , powMod
) where

import System.Random

-- | Usage: prime (maxBound) :: IO Word64

prime :: (Num a, Integral a) => a -> IO a
prime max = do
  g <- newStdGen
  g' <- newStdGen
  let candidates = randomRs (2,fromIntegral max) g
  let tests = take 20 $ randoms g
  return $ fromIntegral $ head $ filter (\c -> all (millerRabinPrimality c) (map (\a -> (a `mod` (fromIntegral c - 3)) + 2) tests)) candidates


--------------------------------------------------------------------------------
-- Copied from: http://www.haskell.org/haskellwiki/Testing_primality
--------------------------------------------------------------------------------

-- (eq. to) find2km (2^k * n) = (k,n)
find2km :: Integral a => a -> (a,a)
find2km n = f 0 n
    where 
        f k m
            | r == 1 = (k,m)
            | otherwise = f (k+1) q
            where (q,r) = quotRem m 2        
 
-- n is the number to test; a is the (presumably randomly chosen) witness
millerRabinPrimality :: Integer -> Integer -> Bool
millerRabinPrimality n a
    | a <= 1 || a >= n-1 = 
        error $ "millerRabinPrimality: a out of range (" 
              ++ show a ++ " for "++ show n ++ ")" 
    | n < 2 = False
    | even n = False
    | b0 == 1 || b0 == n' = True
    | otherwise = iter (tail b)
    where
        n' = n-1
        (k,m) = find2km n'
        b0 = powMod n a m
        b = take (fromIntegral k) $ iterate (squareMod n) b0
        iter [] = False
        iter (x:xs)
            | x == 1 = False
            | x == n' = True
            | otherwise = iter xs
 
-- (eq. to) pow' (*) (^2) n k = n^k
pow' :: (Num a, Integral b) => (a->a->a) -> (a->a) -> a -> b -> a
pow' _ _ _ 0 = 1
pow' mul sq x' n' = f x' n' 1
    where 
        f x n y
            | n == 1 = x `mul` y
            | r == 0 = f x2 q y
            | otherwise = f x2 q (x `mul` y)
            where
                (q,r) = quotRem n 2
                x2 = sq x
 
mulMod :: Integral a => a -> a -> a -> a
mulMod a b c = (b * c) `mod` a
squareMod :: Integral a => a -> a -> a
squareMod a b = (b * b) `rem` a
 
-- (eq. to) powMod m n k = n^k `mod` m
powMod :: Integral a => a -> a -> a -> a
powMod m = pow' (mulMod m) (squareMod m)
