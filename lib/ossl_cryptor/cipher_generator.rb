require "openssl"

# Cipher instance generator.
module CipherGenerator

  # default pass.
  DEFAULT_PASS = "ossl_cryptor"

  # default hash algorithm.
  DEFAULT_KEY_IV_HASH = "sha256"

  # generate cipher instance.
  # @param [String] mode crypt mode.
  # @return [Cipher] cipher instance.
  def self.generate_cipher(mode)
    cipher = OpenSSL::Cipher.new(mode)
    cipher
  end

  # generate random key and iv.
  # @param [String] mode crypt mode.
  # @return [Hash] key and iv hash. xx[:key] = key, xx[:iv] = iv
  def self.generate_random_key_iv(mode)
    cipher = OpenSSL::Cipher.new(mode)
    key_iv = { key: cipher.random_key, iv: cipher.random_iv }
  end
end