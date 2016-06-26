require "openssl"

# Cipher instance generator.
module CipherGenerator

  # default pass.
  DEFAULT_PASS = "ossl_cryptor"

  # default hash algorithm.
  DEFAULT_KEY_IV_HASH = "sha256"

  # generate cipher instance.
  # @return [Cipher] cipher instance.
  def self.generate_cipher(mode)
    cipher = OpenSSL::Cipher.new(mode)
    cipher
  end
end