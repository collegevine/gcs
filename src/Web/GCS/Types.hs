{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Web.GCS.Types where

import Control.Lens.TH
import Control.Monad (mzero)
import Crypto.PubKey.RSA.Types (PrivateKey)
import Data.Aeson

data GcsCfg = GcsCfg {
    _gcsCfgBucket :: String,
    _gcsCfgEmail :: String,
    _gcsPrivateKey :: PrivateKey
}

data AuthResult = AuthResult String

instance FromJSON AuthResult where
    parseJSON (Object v) = AuthResult <$> v .: "access_token"
    parseJSON _ = mzero

makeClassy ''GcsCfg
