require "ossl_cryptor/version"
require "ossl_cryptor/cryptor"
require "ossl_cryptor/generator"
require "base64"
require "openssl"

# openssl crypt module
module OsslCryptor

  # DES Mode.
  DES = "DES"
  # AES-128-CBC Mode.
  AES_128 = "AES-128-CBC"
  # AES-256-CBC Mode.
  AES_256 = "AES-256-CBC"

  # RFC2045
  RFC2045 = 0
  # RFC4648
  RFC4648 = 1

  # @return [String] availabe cipher.
  def self.available
    "#{AES_128}, #{AES_256}, #{DES}"
  end
end
