{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Web.GCS(
    list,
    upload,
    download,
    downloadURL,
    getSignedURL
) where

import Web.GCS.Types

import Control.Lens (view, each, to, (^?), (^..))
import Control.Monad.Except (MonadError)
import Control.Monad.Reader (MonadReader)
import Control.Monad.Trans (MonadIO, liftIO)
import Crypto.Hash.Algorithms (SHA256(..))
import Crypto.PubKey.RSA.PKCS15 (sign)
import Data.Aeson hiding (Array)
import Data.Aeson.Lens (key, _Array, _String)
import Data.DList (DList)
import Data.Monoid
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.HTTP.Nano
import Network.URI (escapeURIString)
import qualified Data.ByteString.Base64     as B64R
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Char8      as B
import qualified Data.ByteString.Lazy.Char8 as BL
import qualified Data.DList                 as D
import qualified Data.Text                  as T

-- | Get collection of files in bucket.

list
  :: forall m e r. ( MonadIO m
     , MonadError e m
     , AsHttpError e
     , MonadReader r m
     , HasGcsCfg r
     , HasHttpCfg r )
  => m [FilePath]
list = do
  bucket <- view gcsCfgBucket
  let getNames :: Value -> [FilePath]
      getNames v = v ^.. key "items" . _Array . each . key "name" . _String . to T.unpack
      go :: Maybe String -> m (DList FilePath)
      go ptoken = do
        let url = "https://www.googleapis.com/storage/v1/b/" <> bucket <> "/o"
              <> maybe "" ("?pageToken=" ++) ptoken
        r <- (httpJSON =<< buildGCSReq GET url NoRequestData) :: m Value
        case r ^? (key "nextPageToken" . _String . to T.unpack) of
          Nothing -> (return . D.fromList . getNames) r
          Just ptoken' -> (D.fromList (getNames r) <>) <$> go (pure ptoken')
  D.toList <$> go Nothing

-- |Upload an object
upload :: (MonadIO m, MonadError e m, AsHttpError e, MonadReader r m, HasGcsCfg r, HasHttpCfg r) => String -> String -> BL.ByteString -> m ()
upload mime name dta = do
    bucket <- view gcsCfgBucket
    let url = "https://www.googleapis.com/upload/storage/v1/b/"<>
          bucket<>"/o?uploadType=media&name="<> escapeName name
    req <- addHeaders [("Content-Type", mime),("Content-length", show $ BL.length dta)] <$> buildGCSReq POST url (RawRequestData dta)
    http' req

-- |Download an object
download :: (MonadIO m, MonadError e m, AsHttpError e, MonadReader r m, HasGcsCfg r, HasHttpCfg r) => String -> m BL.ByteString
download name = do
    bucket <- view gcsCfgBucket
    downloadURL $ "https://www.googleapis.com/storage/v1/b/"<>bucket<>"/o/"<>
      escapeName name <>"?alt=media"

-- |Download from a URL
downloadURL :: (MonadIO m, MonadError e m, AsHttpError e, MonadReader r m, HasGcsCfg r, HasHttpCfg r) => String -> m BL.ByteString
downloadURL url = do
    req <- buildGCSReq GET url NoRequestData
    http req

-- |Get a signed URL for an object
getSignedURL :: (MonadError e m, MonadReader r m, HasGcsCfg r) => String -> Int -> m String
getSignedURL name expUTC = do
    (GcsCfg bucket email pkey) <- view gcsCfg
    let path = "/"<>bucket<>"/"<>escapeName name
    let str = B.pack $ mconcat ["GET\n", "\n", "\n", show expUTC<>"\n", path]
    let sig = either (const "") B64R.encode $ sign Nothing (Just SHA256) pkey str
    let esig = T.unpack . T.replace "+" "%2B" . T.replace "/" "%2F" . T.pack $ B.unpack sig
    return $
        mconcat [
            "http://storage.googleapis.com",
            path,
            "?GoogleAccessId=",
            email,
            "&Expires=",
            show expUTC,
            "&Signature=",
            esig
        ]

--
-- Utility
--

buildGCSReq :: (MonadIO m, MonadError e m, AsHttpError e, MonadReader r m, HasGcsCfg r, HasHttpCfg r) => HttpMethod -> String -> RequestData -> m Request
buildGCSReq mthd url dta = do
    tok <- getGCSAccessToken
    addHeaders [("Authorization", "Bearer "++tok)] <$> buildReq mthd url dta

getGCSAccessToken :: (MonadIO m, MonadError e m, AsHttpError e, MonadReader r m, HasGcsCfg r, HasHttpCfg r) => m String
getGCSAccessToken  = do
    jwt <- getGCSJWT
    req <- buildReq POST "https://www.googleapis.com/oauth2/v4/token" (UrlEncodedRequestData [("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),("assertion", jwt)])
    (AuthResult tok) <- httpJSON req
    return tok

getGCSJWT :: (MonadIO m, MonadError e m, AsHttpError e, MonadReader r m, HasGcsCfg r, HasHttpCfg r) => m String
getGCSJWT = do
    tme <- liftIO $ (round <$> getPOSIXTime :: IO Int)
    (GcsCfg _ email pkey) <- view gcsCfg
    let obj = object ["iss" .= email, "scope" .= ("https://www.googleapis.com/auth/devstorage.read_write" :: String), "aud" .= ("https://www.googleapis.com/oauth2/v4/token" :: String), "exp" .= (tme + 3590), "iat" .= tme]
    let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    let body = B64.encode . BL.toStrict $ encode obj
    let sig = either (const "") B64.encode $ sign Nothing (Just SHA256) pkey (header<>"."<>body)
    return . B.unpack $ header<>"."<>body<>"."<>sig

escapeName :: String -> String
escapeName = escapeURIString f
    where
        f x | x `elem` ['A'..'Z'] = True
            | x `elem` ['a'..'z'] = True
            | x `elem` ['0'..'9'] = True
            | x `elem` ("-._~!$&\'()*+,;=:@" :: String) = True
            | otherwise = False
