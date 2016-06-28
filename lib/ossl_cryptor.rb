require "ossl_cryptor/version"
require "ossl_cryptor/cipher_generator"
require "base64"
require "openssl"

# openssl crypt module
module OsslCryptor

  # DES Mode.
  DES = "DES"
  # AES Mode.
  AES = "AES-256-CBC"

  # Crypt class
  class Cryptor

    # constructor.
    # @param [String] mode cipher mode.
    # @param [Hash] key_iv key and iv. key_iv[:key] = key, key_iv[:iv] = iv
    # @param [String] pass password
    # @param [String] salt salt data. if salt is nil, use random salt.
    # @param [String] key_iv_hash use hash algorithm when key and iv generate.
    def initialize(mode, key_iv=nil, pass=nil, salt=nil, key_iv_hash=nil)

      # if invalid mode, raise error.
      if (AES != mode) && (DES != mode)
        raise OpenSSL::Cipher::CipherError "invalid mode : #{mode}"
      end

      # generate cipher instance.
      @cipher = CipherGenerator.generate_cipher(mode)
      # set initialize parameter and generate key, iv
      @mode = mode
      @default_key_iv = key_iv
      @pass = pass.nil? ? CipherGenerator::DEFAULT_PASS : pass
      @salt = salt
      @key_iv_hash = key_iv_hash.nil? ? CipherGenerator::DEFAULT_KEY_IV_HASH : key_iv_hash
      @key_iv = generate_key_iv(@mode, @default_key_iv, @pass, @salt, @key_iv_hash)
    end

    # reset cipher instance.
    def reset
      @cipher = CipherGenerator.generate_cipher(@mode)
      @key_iv = generate_key_iv(@mode, @default_key_iv, @pass, @salt, @key_iv_hash)
    end

    # encrypt value.
    # @param [String] value encrypt value.
    # @return [String] encrypt result value.
    def encrypt(value, encode_base64=true)

      # prepare encrypt.
      @cipher.encrypt
      set_key_iv

      # encrypt.
      encrypt_value = ""
      encrypt_value << @cipher.update(value)
      encrypt_value << @cipher.final
      
      # encode base64.
      if encode_base64
        encrypt_value = Base64.encode64(encrypt_value)
      end

      encrypt_value
    end

    # decrypt value.
    # @param [String] value decrypt value.
    # @return [String] decrypt result value.
    def decrypt(value, decode_base64=true)

      # prepare decrypt.
      @cipher.decrypt
      set_key_iv

      # decode base64.
      if decode_base64
        value = Base64.decode64(value)
      end

      # decrypt.
      decrypt_value = ""
      decrypt_value << @cipher.update(value)
      decrypt_value << @cipher.final
      decrypt_value
    end

    # get crypt mode.
    # @return [String] mode
    def mode
      @mode
    end

    # get key and iv.
    # @return [Hash] key and iv. key_iv[:key] = key, key_iv[:iv] = iv
    def key_iv
      @key_iv
    end

    private

    # setup cipher instance.
    # @param [String] mode crypt mode.
    # @param [Hash] key_iv key and iv. key_iv[:key] = key, key_iv[:iv] = iv
    # @param [String] pass password, if pass = nil, use CipherGenerator::DEFAULT_PASS
    # @param [String] salt salt data. if salt = nil, use random salt.
    # @param [String] hash use hash algorithm when key and iv generate. if key_iv_hash = nil, use CipherGenerator::DEFAULT_KEY_IV_HASH
    # @return [Hash] key and iv hash.
    def generate_key_iv(mode, key_iv=nil, pass=nil, salt=nil, hash=nil)

      cipher_key_iv = nil

      # if key_iv = nil, generate key and iv.
      if key_iv.nil?
        salt = salt.nil? ? get_default_salt(mode) : salt
        key_iv_str = OpenSSL::PKCS5.pbkdf2_hmac(pass, salt, 2000, (@cipher.key_len + @cipher.iv_len), hash)
        key = key_iv_str[0, @cipher.key_len]
        iv = key_iv_str[@cipher.key_len, @cipher.iv_len]
        cipher_key_iv = { key: key, iv: iv }
      else
        cipher_key_iv = key_iv
      end

      cipher_key_iv
    end

    # get default salt depend on mode.
    # @param [String] mode cipher mode.
    # @return [String] default salt.
    def get_default_salt(mode)

      default_salt = nil

      if mode == AES
        default_salt = OpenSSL::Random.random_bytes(8)
      elsif mode == DES
        default_salt = OpenSSL::Random.random_bytes(2)
      end

      default_salt
    end

    # set key and iv to cipher instance.
    def set_key_iv
      @cipher.key = @key_iv[:key]
      @cipher.iv = @key_iv[:iv]
    end
  end

  # get available crypt mode.
  # @return [String] availabe cipher.
  def self.available
    "#{AES}, #{DES}"
  end
end
