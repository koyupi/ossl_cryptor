require "ossl_cryptor/version"
require "ossl_cryptor/cryptor"
require "ossl_cryptor/generator"
require "base64"
require "openssl"

# openssl crypt module
module OsslCryptor

  # DES Mode.
  DES = "DES"
  # AES Mode.
  AES = "AES-256-CBC"

  # RFC2045
  RFC2045 = 0
  # RFC4648
  RFC4648 = 1

  # @return [String] availabe cipher.
  def self.available
    "#{AES}, #{DES}"
  end
end
