{-|
Module      : Crypto.Minio.Dare
Description : Implements the Data-At-Rest-Encryption specification.
License     : Apache License v2.0
Stability   : Experimental

This module provides functions to encrypt or decrypt bytestrings
according to the Data-At-Rest-Encryption (DARE) specification -
<https://github.com/minio/sio/blob/master/DARE.md>.

Both Authenticated Encryption with Associated Data (AEAD) ciphers from
the specification, i.e AES-256 GCM and CHACHA20-Poly1305 are
supported.
-}
module Crypto.Minio.Dare (
  -- * Ciphers
  SupportedCipher(..)
  -- * Encryption
  -- ** Initialization
  , EncryptionParams
  , newEncryptionParams
  , getNonce
  -- ** Encryption functions
  , encryptStream
  , encryptLazyBS
  -- * Decryption
  -- ** Initialization
  , DecryptionKey
  , newDecryptionKey
  -- ** Decryption functions
  , decryptStream
  , decryptLazyBS
  -- * Errors
  , DErr(..)
  ) where

import           Lib.Prelude

import qualified Data.Binary         as Bin
import           Data.Binary.Get     (getWord16le, getWord32le)
import           Data.Binary.Put     (putWord16le, putWord32le)
import qualified Data.ByteString     as B
import qualified Data.ByteString.Lazy     as LB
import qualified Data.Text as T
import qualified Conduit as C
import qualified Data.Conduit.List as CL
import           Control.Monad.Catch (MonadThrow, throwM)
import           Crypto.Cipher.AES   (AES256)
import           Crypto.Random.Entropy    (getEntropy)
import qualified Crypto.MAC.Poly1305 as CP
import qualified Crypto.Cipher.ChaChaPoly1305 as CCP
import           Crypto.Cipher.Types (AEAD (..), BlockCipher (..))
import qualified Crypto.Cipher.Types as CT
import           Crypto.Error        (CryptoError (..), CryptoFailable (..))
import qualified Data.ByteArray      as BA

headerLen :: Int
headerLen = 16

tagLen :: Int
tagLen = 16

maxPayloadLen :: Int
maxPayloadLen = 65536 -- 2^16

dareVersion :: Word8
dareVersion = 0x10

ciph_AES_256_GCM :: Word8
ciph_AES_256_GCM = 0x00

ciph_CHACHA20_POLY1305 :: Word8
ciph_CHACHA20_POLY1305 = 0x10

type EncryptFunc = (BA.ScrubbedBytes -> -- key (32 bytes)
                    BA.Bytes -> -- nonce (8 bytes)
                    ByteString -> -- auth header
                    ByteString -> -- plain text
                    (ByteString, BA.Bytes)) -- enc. text and auth tag
type DecryptFunc = (BA.ScrubbedBytes -> -- key (32 bytes)
                    BA.Bytes -> -- nonce (8 bytes)
                    ByteString -> -- auth header
                    ByteString -> -- cipher text
                    BA.Bytes -> -- auth tag
                    Maybe ByteString) -- dec. plain text if data valid

type DareCipher = (EncryptFunc, DecryptFunc)

-- | Data type representing a supported AEAD cipher.
data SupportedCipher
  = AES_256_GCM        -- | AES-256 in Galois Counter Mode
  | CHACHA20_POLY1305 -- | ChaCha20 and Poly1305
  deriving (Eq, Show)

toCode :: SupportedCipher -> Word8
toCode AES_256_GCM = ciph_AES_256_GCM
toCode CHACHA20_POLY1305 = ciph_CHACHA20_POLY1305

ciphers :: Word8 -> Maybe DareCipher
ciphers w | w == ciph_AES_256_GCM =
              Just (encryptAES256GCM, decryptAES256GCM)
          | w == ciph_CHACHA20_POLY1305 =
              Just (encryptCC20P1305, decryptCC20P1305)
          | otherwise = Nothing

data Header = HeaderV1
              Word8 -- version byte
              Word8 -- cipher code byte
              Int -- payload length
              Word32 -- sequence number
              BA.Bytes -- nonce (8-byte)

instance Bin.Binary Header where
  put (HeaderV1 v c size sno nonce) =
    do Bin.put v
       Bin.put c
       putWord16le (fromIntegral $ size - 1)
       putWord32le sno
       mapM_ Bin.put $ BA.unpack nonce
  get = do v <- Bin.get
           c <- Bin.get
           size <- (1+) . fromIntegral <$> getWord16le
           sno <- getWord32le
           nonce <- BA.pack <$> replicateM 8 Bin.getWord8
           return $ HeaderV1 v c size sno nonce

-- | A data type to specify encryption parameters. It does not export
-- any constructors. Use the @newEncryptionParams@ smart constructor
-- to make an EncryptionParams value.
data EncryptionParams = EP
                        SupportedCipher -- cipher choice
                        DareCipher -- cipher funcs
                        BA.ScrubbedBytes -- key
                        BA.Bytes -- nonce

-- | Create an @EncryptionParams@ value after validating the chosen
-- cipher, key and nonce.
newEncryptionParams :: SupportedCipher -> BA.ScrubbedBytes -> BA.Bytes
                    -> Either DErr EncryptionParams
newEncryptionParams !chosenCipher !key !nonce = do
  when (BA.length key /= 32) $ Left DEInvalidKeyLength
  when (BA.length nonce /= 8) $ Left DEInvalidNonceLength
  let cipherCode = toCode chosenCipher
  cipher <- maybe (Left DEUnsupportedCipher) return $ ciphers cipherCode
  return $ EP chosenCipher cipher key nonce

-- | A helper that randomly generates an 8-byte nonce required for
-- @newEncryptionParams@.
getNonce :: IO BA.Bytes
getNonce = getEntropy 8

-- | A conduit that encrypts bytes received from upstream and sends
-- cipher-text downstream. It can be used to encrypt a stream of bytes
-- in a constant amount of memory.
--
-- As an example, using the `conduit-extra` package, encrypting a file
-- is as simple as:
--
--   > sourceFile "plain.txt" =$= encryptStream encParams
--         $$ sinkFileCautious "cipher.txt"
encryptStream :: Monad m => EncryptionParams -> C.Conduit ByteString m ByteString
encryptStream (EP ch c k nonce) = processStream 0
  where
    collect !need !bsList = do
      v <- C.await
      case v of
        Just b ->
          if B.length b < need
          then collect (need - B.length b) (b:bsList)
          else do let (req, extra) = B.splitAt need b
                  when (B.length extra > 0) $ C.leftover extra
                  return $ B.concat $ reverse (req:bsList)
        Nothing -> return $ B.concat $ reverse bsList

    encrypt n bs =
      let
        header = HeaderV1 dareVersion (toCode ch)
                 (fromIntegral $ B.length bs)
                 n nonce
        encodedHeader = toS $ Bin.encode header
        (aeadHeader, aeadNonce) = B.splitAt 4 encodedHeader
        encFunc = fst c
        (encText, authTag) = encFunc k (BA.convert aeadNonce) aeadHeader
                             bs
      in
        B.concat [encodedHeader, encText, BA.convert authTag]

    processStream n = do
      bs <- collect maxPayloadLen []
      if B.length bs == 0
        then return ()
        else C.yield (encrypt n bs) >> processStream (n+1)

-- | Encrypt a lazy bytestring. It is an alternative to using
-- conduits, but is otherwise identical.
encryptLazyBS :: EncryptionParams -> LByteString -> LByteString
encryptLazyBS ep lbs = C.runConduitPure $ source C.=$= encryptStream ep
                       C.$$ C.sinkLazy
  where
    source = CL.sourceList $ LB.toChunks lbs

-- | A data type to specify the key in a decryption operation. No
-- constructors are exported. Use the @newDecryptionKey@ smart
-- constructor to create a DecryptionKey value.
data DecryptionKey = DK BA.ScrubbedBytes -- key

-- | Create a @DecryptionKey@ after validating the provided key.
newDecryptionKey :: BA.ScrubbedBytes -> Either DErr DecryptionKey
newDecryptionKey !key = do
  when (BA.length key /= 32) $ Left DEInvalidKeyLength
  return $ DK key

-- | A conduit that decrypts bytes received from upstream and sends
-- plain text downstream. It can be used to decrypt a stream of bytes
-- in a constant amount of memory. It throws an error and exits on the
-- first error encountered.
--
-- As an example, using the `conduit-extra` package, decrypting a file
-- is as simple as:
--
--   > sourceFile "cipher.txt" =$= decryptStream key
--         $$ sinkFileCautious "decrypted.txt"
decryptStream :: MonadThrow m => DecryptionKey
              -> C.Conduit ByteString m ByteString
decryptStream (DK key) = decryptPkg 0
  where
    maxPkgLen = headerLen + maxPayloadLen + tagLen

    collect !need !bsList = do
      v <- C.await
      case v of
        Just b ->
          if B.length b < need
          then collect (need - B.length b) (b:bsList)
          else do let (req, extra) = B.splitAt need b
                  when (B.length extra > 0) $ C.leftover extra
                  return $ B.concat $ reverse (req:bsList)
        Nothing -> return $ B.concat $ reverse bsList

    checkLen n err bs = when (B.length bs /= n) $ throwM err

    -- returns (Decrypt.Func, payload length) once header is validated
    readHeader hbytes n = do
      checkLen headerLen DEHeaderTooShort hbytes
      let (HeaderV1 v c size seqno _) = Bin.decode $ toS hbytes
      if | v /= dareVersion -> throwM DEUnsupportedVersion
         | n /= seqno -> throwM DEPackageOutOfOrder
         | otherwise -> maybe (throwM DEUnsupportedCipher)
                        (return . fmap (const size) . swap) $
                        ciphers c

    decryptPayload decFunc hbytes cipherText authTag = do
      let (aeadHeader, aeadNonce) = B.splitAt 4 hbytes
          plainMay = decFunc key (BA.convert aeadNonce) aeadHeader
                     cipherText (BA.convert authTag)
      maybe (throwM DEDecryptionFailed) C.yield plainMay

    decryptPkg !n = do
      bs <- collect maxPkgLen []
      if B.length bs == 0 then return ()
        else do let (hbytes, r1) = B.splitAt headerLen bs
                (decFunc, payloadLen) <- readHeader hbytes n
                let (payload, r2) = B.splitAt payloadLen r1
                    (authTag, r3) = B.splitAt tagLen r2
                checkLen payloadLen DEPayloadTooShort payload
                checkLen tagLen DEAuthTagTooShort authTag
                decryptPayload decFunc hbytes payload authTag
                when (B.length r3 > 0) $ C.leftover r3
                decryptPkg $ n+1

-- | Decrypt a lazy bytestring. It is an alternative to using
-- conduits, but is otherwise identical. If an error is encountered,
-- it returns Nothing.
decryptLazyBS :: DecryptionKey -> LByteString -> Maybe LByteString
decryptLazyBS dp lbs = source C.=$= decryptStream dp C.$$ C.sinkLazy
  where
    source = CL.sourceList $ LB.toChunks lbs

-- A data type representing errors returned/thrown by the this module.
data DErr
  = DEDecryptionFailed
  | DEUnsupportedVersion
  | DEUnsupportedCipher
  | DEInvalidKeyLength
  | DEInvalidNonceLength
  | DEHeaderTooShort
  | DEPayloadTooShort
  | DEAuthTagTooShort
  | DEPackageOutOfOrder
  | DECryptoUnexpected CryptoError -- ^ This error will not normally
                                   -- be thrown (please report a bug!)
  deriving (Eq, Show)

instance Exception DErr

cryptoEither :: CryptoFailable a -> Either DErr a
cryptoEither (CryptoFailed e) = Left (DECryptoUnexpected e)
cryptoEither (CryptoPassed c) = Right c

encryptAES256GCM :: BA.ScrubbedBytes -- key
                 -> BA.Bytes -- nonce
                 -> ByteString -- associated data
                 -> ByteString -- plaintext

                 -- on success, encrypted data and auth tag;
                 -- on error, throws error message (cannot be handled).
                 -> (ByteString, BA.Bytes)
encryptAES256GCM key nonce header plainText =
  let
    aeadE = do
      cipher <- cryptoEither (CT.cipherInit key :: CryptoFailable AES256)
      cryptoEither (aeadInit CT.AEAD_GCM cipher nonce :: CryptoFailable (AEAD AES256))

    encrypt aead = CT.aeadSimpleEncrypt aead header plainText 16

  in
    either
      (error . T.append "Unexpected encryption failure: " . T.pack . show)
      (fmap CT.unAuthTag . swap . encrypt)
      aeadE

decryptAES256GCM :: BA.ScrubbedBytes -- key
                 -> BA.Bytes -- nonce
                 -> ByteString -- associated data
                 -> ByteString -- ciphertext
                 -> BA.Bytes -- authentication tag
                 -- return decrypted text if auth tag valid
                 -> Maybe ByteString
decryptAES256GCM key nonce header cipherText authTag =
  let
    aeadE = do
      cipher <- cryptoEither (CT.cipherInit key :: CryptoFailable AES256)
      cryptoEither (aeadInit CT.AEAD_GCM cipher nonce :: CryptoFailable (AEAD AES256))

    decrypt aead = CT.aeadSimpleDecrypt aead header cipherText (CT.AuthTag authTag)
  in
    either
      (error . T.append "Unexpected decryption failure: " . T.pack . show)
      decrypt
      aeadE

encryptCC20P1305 :: BA.ScrubbedBytes -- key
                 -> BA.Bytes -- nonce
                 -> ByteString -- associated data
                 -> ByteString -- plaintext

                 -- on success, encrypted data and auth tag;
                 -- on error, throws error message (cannot be handled).
                 -> (ByteString, BA.Bytes)
encryptCC20P1305 key nonce header plainText =
  let
    stEither = cryptoEither $ CCP.nonce12 nonce >>= CCP.initialize key
    headerState = CCP.finalizeAAD . CCP.appendAAD header

  in
    either
      (error . T.append "Unexpected encryption failure: " . T.pack . show)
      (fmap (BA.convert . CCP.finalize) . CCP.encrypt plainText . headerState)
      stEither

decryptCC20P1305 :: BA.ScrubbedBytes -- key
                 -> BA.Bytes -- nonce
                 -> ByteString -- associated data
                 -> ByteString -- ciphertext
                 -> BA.Bytes -- authentication tag
                 -- return decrypted text if auth tag valid
                 -> Maybe ByteString
decryptCC20P1305 key nonce header cipherText authTag =
  let
    stEither = cryptoEither $ CCP.nonce12 nonce >>= CCP.initialize key
    headerState = CCP.finalizeAAD . CCP.appendAAD header
    checkAuth (plainText, t) = bool Nothing (Just plainText) $
                               t == CP.Auth authTag

  in
    either
      (error . T.append "Unexpected encryption failure: " . T.pack . show)
      (checkAuth . fmap CCP.finalize . CCP.decrypt cipherText
        . headerState)
      stEither
