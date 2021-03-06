require "ossl_cryptor/generator"
require "base64"
require "openssl"

# openssl crypt module
module OsslCryptor

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
      if (AES_128 != mode) && (AES_256 != mode) && (DES != mode)
        raise OpenSSL::Cipher::CipherError.new("invalid mode : #{mode}")
      end

      # generate cipher instance.
      @cipher = OsslCryptor::Generator.generate_cipher(mode)
      # set initialize parameter and generate key, iv
      @mode = mode
      @pass = pass.nil? ? OsslCryptor::Generator::DEFAULT_PASS : pass
      @salt = salt
      @key_iv_hash = key_iv_hash.nil? ? OsslCryptor::Generator::DEFAULT_KEY_IV_HASH : key_iv_hash
      @key_iv = key_iv.nil? ? generate_key_iv(@mode, @pass, @salt, @key_iv_hash) : key_iv
    end

    # reset cipher instance.
    def reset
      @cipher = OsslCryptor::Generator.generate_cipher(@mode)
      @key_iv = generate_key_iv(@mode, @pass, @salt, @key_iv_hash) if @key_iv.nil?
    end

    # encrypt value.
    # @param [String] value encrypt value.
    # @param [boolean] encode_base64 encode base64 flag.
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
        encrypt_value = encode_base64(encrypt_value)
      end

      encrypt_value
    end

    # decrypt value.
    # @param [String] value decrypt value.
    # @param [boolean] decode_base64 decode base64 flag.
    # @return [String] decrypt result value.
    def decrypt(value, decode_base64=true)

      # prepare decrypt.
      @cipher.decrypt
      set_key_iv

      # decode base64.
      if decode_base64
        value = decode_base64(value)
      end

      # decrypt.
      decrypt_value = ""
      decrypt_value << @cipher.update(value)
      decrypt_value << @cipher.final
      decrypt_value
    end

    # encrypt value and save to file.
    # @param [String] file_path save file path.
    # @param [String] value encrypt value.
    # @param [boolean] encode_base64 encode base64 flag.
    # @return [String] encrypt result value.
    def encrypt_to_file(file_path, value, encode_base64=true)

      # encrypt value.
      enc_value = encrypt(value, encode_base64)

      # save file.
      File.write(file_path, enc_value)
      enc_value
    end

    # decrypt value from file.
    # @param [String] file_path save file path.
    # @param [boolean] decode_base64 decode base64 flag.
    # @return [String] decrypt result value.
    def decrypt_from_file(file_path, decode_base64=true)

      # read from file.
      enc_value = File.read(file_path)

      dec_value = decrypt(enc_value, decode_base64)
      dec_value
    end

    # set base64 rfc.
    # @param [integer] rfc rfc
    def set_rfc(rfc)
      @rfc = rfc
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

    # generate cipher key and iv.
    # @param [String] mode crypt mode.
    # @param [String] pass password, if pass = nil, use OsslCryptor::Generator::DEFAULT_PASS
    # @param [String] salt salt data. if salt = nil, use random salt.
    # @param [String] hash use hash algorithm when key and iv generate. if key_iv_hash = nil, use OsslCryptor::Generator::DEFAULT_KEY_IV_HASH
    # @return [Hash] key and iv hash.
    def generate_key_iv(mode, pass=nil, salt=nil, hash=nil)

      salt = salt.nil? ? get_default_salt(mode) : salt
      key_iv_str = OpenSSL::PKCS5.pbkdf2_hmac(pass, salt, 2000, (@cipher.key_len + @cipher.iv_len), hash)
      key = key_iv_str[0, @cipher.key_len]
      iv = key_iv_str[@cipher.key_len, @cipher.iv_len]
      cipher_key_iv = { key: key, iv: iv }

      cipher_key_iv
    end

    # get default salt depend on mode.
    # @param [String] mode cipher mode.
    # @return [String] default salt.
    def get_default_salt(mode)

      default_salt = nil

      if (mode == AES_128) || (mode == AES_256)
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

    # encode base64.
    # @param [String] value target value.
    # @return [String] base64 encode value.
    def encode_base64(value)

      if @rfc == RFC2045
        Base64.encode64(value)
      elsif @rfc == RFC4648
        Base64.strict_encode64(value)
      else
        Base64.encode64(value)
      end
    end

    # decode base64.
    # @param [String] value target value.
    # @return [String] base64 decode value.
    def decode_base64(value)

      if @rfc == RFC2045
        Base64.decode64(value)
      elsif @rfc == RFC4648
        Base64.strict_decode64(value)
      else
        Base64.decode64(value)
      end
    end
  end
end
