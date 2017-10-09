module Main where

import           Crypto.Minio.Dare
import           Protolude

import qualified Crypto.KDF.Scrypt        as Scrypt
import           Crypto.Random.Entropy    (getEntropy)
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as B
import qualified Data.ByteString.Char8    as B8
import           Data.Conduit             (($$), (=$=))
import qualified Data.Conduit.Binary      as CB
import           Options.Applicative
import           System.Console.Haskeline (defaultSettings, getPassword,
                                           preferTerm, runInputTBehavior)
import           System.IO                (IOMode (..), stdin, stdout)
import qualified System.IO                as Sys


data DataArg = DA FilePath
             | DAStdin
             | DAStdout
             deriving (Eq, Show)

showDA :: DataArg -> [Char]
showDA (DA p)   = p
showDA DAStdin  = "stdin"
showDA DAStdout = "stdout"

getDAHandle :: DataArg -> IOMode -> IO Handle
getDAHandle (DA p) mode = Sys.openBinaryFile p mode
getDAHandle DAStdin _   = return stdin
getDAHandle DAStdout _  = return stdout

readCipher :: [Char] -> Either [Char] SupportedCipher
readCipher s
  | s == show AES_256_GCM = Right AES_256_GCM
  | s == show CHACHA20_POLY1305 = Right CHACHA20_POLY1305
  | otherwise = Left "Invalid cipher given!"

data ProgramConfig = ProgramConfig
  { isDecrypt :: Bool
  , cipher    :: SupportedCipher
  , isList    :: Bool
  , srcArg    :: DataArg
  , dstArg    :: DataArg
  } deriving (Show, Eq)

programConfig :: Parser ProgramConfig
programConfig = ProgramConfig
             <$> switch
                 ( long "decrypt"
                <> short 'd'
                <> help "Decrypt the source")
             <*> option (eitherReader readCipher)
                 ( long "cipher"
                <> short 'c'
                <> metavar "CIPHER"
                <> value AES_256_GCM
                <> showDefault
                <> help "Specify cipher")
             <*> switch
                 ( long "list"
                <> short 'l'
                <> help "List supported ciphers")
             <*> option (eitherReader (Right . DA))
                 ( long "source-file"
                <> short 'f'
                <> metavar "SOURCE-FILENAME"
                <> value DAStdin
                <> showDefaultWith showDA
                <> help "Source file to encrypt or decrypt")
             <*> option (eitherReader (Right . DA))
                 ( long "dest-file"
                <> short 'o'
                <> metavar "DEST-FILENAME"
                <> value DAStdout
                <> showDefaultWith showDA
                <> help "Destination to write output to")

opts :: ParserInfo ProgramConfig
opts = info (programConfig <**> helper)
       ( fullDesc
      <> progDesc "This program implements the Data-At-Rest-Encryption (DARE) specification - https://github.com/minio/sio/blob/master/DARE.md"
      <> header "A tool to encrypt or decrypt data according to the DARE specification.")

readPassword :: IO (Maybe BA.ScrubbedBytes)
readPassword = runInputTBehavior preferTerm defaultSettings $ do
  pwMaybe <- getPassword (Just '*') "Enter password: "
  return $ fmap (BA.convert . B8.pack) pwMaybe

deriveKey :: ProgramConfig -> Handle
          -> IO (Maybe (BA.ScrubbedBytes, ByteString))
deriveKey pc srcHdl = do
  pwMay <- readPassword
  case pwMay of
    Nothing -> return Nothing
    Just pw -> do
      salt <- bool (getEntropy 32) (B.hGet srcHdl 32) $ isDecrypt pc
      return $ Just (Scrypt.generate params pw salt, salt)
  where
    params = Scrypt.Parameters 32768 16 1 32

main :: IO ()
main = do
  pc <- execParser opts

  if isList pc
    then do B8.putStrLn "The following ciphers are supported:"
            mapM_ print [AES_256_GCM, CHACHA20_POLY1305]
    else run pc

  where
    run pc = do
      srcHdl <- getDAHandle (srcArg pc) ReadMode
      dstHdl <- getDAHandle (dstArg pc) WriteMode

      (key, salt) <- maybe (error "Could not read password")
                     identity <$> deriveKey pc srcHdl

      if isDecrypt pc
        then do case newDecryptionKey key of
                  Left err -> print err
                  Right dkey -> CB.sourceHandle srcHdl =$=
                                decryptStream dkey $$
                                CB.sinkHandle dstHdl

        else do nonce <- getNonce
                case newEncryptionParams (cipher pc) key nonce of
                  Left err -> print err
                  Right encParms -> do B.hPut dstHdl salt
                                       CB.sourceHandle srcHdl =$=
                                         encryptStream encParms $$
                                         CB.sinkHandle dstHdl

      -- Close write handle at the end.
      Sys.hClose dstHdl
