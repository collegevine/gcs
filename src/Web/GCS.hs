{-# LANGUAGE OverloadedStrings #-}

module Web.GCS(
    upload,
    download,
    downloadURL
) where

import Web.GCS.Types

import Control.Lens (view, (^.))
import Control.Monad (mzero)
import Control.Monad.Except (MonadError)
import Control.Monad.Reader (MonadReader)
import Control.Monad.Trans (MonadIO, liftIO)
import Crypto.Hash.Algorithms (SHA256(..))
import Crypto.PubKey.RSA.PKCS15 (sign)
import Data.Aeson hiding (Array)
import Data.ByteString.Char8 as B
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Monoid
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.HTTP.Nano

-- |Upload an object
upload :: (MonadIO m, MonadError e m, AsHttpError e, MonadReader r m, HasGcsCfg r, HasHttpCfg r) => String -> String -> BL.ByteString -> m ()
upload mime name dta = do
    bucket <- view gcsCfgBucket
    let url = "https://www.googleapis.com/upload/storage/v1/b/"<>bucket<>"/o?uploadType=media&name="<>name
    req <- addHeaders [("Content-Type", mime),("Content-length", show $ BL.length dta)] <$> buildGCSReq POST url (RawRequestData dta)
    http' req

-- |Download an object
download :: (MonadIO m, MonadError e m, AsHttpError e, MonadReader r m, HasGcsCfg r, HasHttpCfg r) => String -> m BL.ByteString
download name = do
    bucket <- view gcsCfgBucket
    downloadURL $ "https://www.googleapis.com/storage/v1/b/"<>bucket<>"/o/"<>name<>"?alt=media"

-- |Download from a URL
downloadURL :: (MonadIO m, MonadError e m, AsHttpError e, MonadReader r m, HasGcsCfg r, HasHttpCfg r) => String -> m BL.ByteString
downloadURL url = do
    req <- buildGCSReq GET url NoRequestData
    http req

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
