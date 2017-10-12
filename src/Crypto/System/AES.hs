{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Crypto.System.AES
Description : Verifies AES-NI instructions
License     : Apache License v2.0
Stability   : Experimental

This module provides function to check AESNI.

-}

module Crypto.System.AES
    (
      supportsAESNI,
     -- Plus, instances exported of course.
    )
where

import Prelude

foreign import ccall unsafe "aes.h" has_aes_ni :: Bool

-- | Does the machine support AESNI instructions?
supportsAESNI :: Bool
supportsAESNI = has_aes_ni

