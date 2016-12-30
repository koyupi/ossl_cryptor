require 'spec_helper'

describe OsslCryptor::Cryptor do

  let(:aes_encrypt_value) { "AES encrypt value" }
  let(:des_encrypt_value) { "DES encrypt value" }
  let(:encrypt_file_path) { 'C:\GitHub\enc.txt' }
  let(:aes_128_key) { '\x9AU\xD5\xE2\xCC7\xE5\t\xA3\xE9\x81\n\xB1\xF8\xDFS' }
  let(:aes_128_iv) { '~!\xD3\b\x19UO\x95H\xDB|*ig\xB0j' }
  let(:aes_256_key) { '\xEEh\xE7!\xBB\xC79\x84\xF7\xDEGw;\x10P\xA4#\xBC\x90A\x05\xC3\xB8\b\x8A\e\x8D\x8A\xA9\xEA\x03K' }
  let(:aes_256_iv) { '\xD7hg\x16\xBB\r\x99S\e_\xF13\xE4KZ&' }
  let(:des_key) { '_\x13\xEBx\xF9\x14\xAAM' }
  let(:des_iv) { '~\x14\x84\x00+4;.' }

  it 'AES-128-CBC test all nil' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_128)
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-128-CBC test appoint pass' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_128, nil, "test_pass")
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-128-CBC test appoint pass and salt' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_128, nil, "test_pass", "salt")
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-128-CBC test appoint pass and salt and hash' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_128, nil, "test_pass", "salt", "md5")
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-128-CBC test appoint key_iv' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_128, { key: aes_128_key, iv: aes_128_iv })
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-128-CBC test non base64' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_128, { key: aes_128_key, iv: aes_128_iv })
    enc_value = cryptor.encrypt(aes_encrypt_value, false)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value, false)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-256-CBC test all nil' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_256)
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-256-CBC test appoint pass' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_256, nil, "test_pass")
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-256-CBC test appoint pass and salt' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_256, nil, "test_pass", "salt")
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-256-CBC test appoint pass and salt and hash' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_256, nil, "test_pass", "salt", "md5")
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-256-CBC test appoint key_iv' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_256, { key: aes_256_key, iv: aes_256_iv })
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES-256-CBC test non base64' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_256, { key: aes_256_key, iv: aes_256_iv })
    enc_value = cryptor.encrypt(aes_encrypt_value, false)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value, false)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'DES test all nil' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::DES)
    enc_value = cryptor.encrypt(des_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq des_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq des_encrypt_value
  end

  it 'DES test appoint pass' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::DES, nil, "test_pass")
    enc_value = cryptor.encrypt(des_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq des_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq des_encrypt_value
  end

  it 'DES test appoint pass and salt' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::DES, nil, "test_pass", "salt")
    enc_value = cryptor.encrypt(des_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq des_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq des_encrypt_value
  end

  it 'DES test appoint pass and salt and hash' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::DES, nil, "test_pass", "salt", "md5")
    enc_value = cryptor.encrypt(des_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq des_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq des_encrypt_value
  end

  it 'DES test appoint key_iv' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::DES, { key: des_key, iv: des_iv })
    enc_value = cryptor.encrypt(des_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq des_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq des_encrypt_value
  end

  it 'DES test non base64' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::DES, { key: des_key, iv: des_iv })
    enc_value = cryptor.encrypt(des_encrypt_value, false)
    # puts enc_value
    expect(enc_value).not_to eq des_encrypt_value

    dec_value = cryptor.decrypt(enc_value, false)
    # puts dec_value
    expect(dec_value).to eq des_encrypt_value
  end

  it 'reset test' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::DES, { key: des_key, iv: des_iv })
    cryptor.reset
    expect(true).to be_truthy
  end

  it 'fail test' do
    expect { cryptor = OsslCryptor::Cryptor.new("SHA1") }.to raise_error(OpenSSL::Cipher::CipherError)
  end

  it 'encrypt to file test' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_256)
    enc_value = cryptor.encrypt_to_file(encrypt_file_path, aes_encrypt_value)
    file_value = File.read(encrypt_file_path)
    # puts file_value
    File.delete(encrypt_file_path)
    expect(enc_value).to eq file_value
  end

  it 'decrypt from file test' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_256)
    cryptor.encrypt_to_file(encrypt_file_path, aes_encrypt_value)
    dec_value = cryptor.decrypt_from_file(encrypt_file_path)
    # puts dec_value
    File.delete(encrypt_file_path)
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'RFC4648 crypt test' do

    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES_256)
    cryptor.set_rfc(OsslCryptor::RFC4648)
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end
end
