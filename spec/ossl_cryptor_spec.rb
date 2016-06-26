require 'spec_helper'

describe OsslCryptor do
  let(:aes_encrypt_value) { "AES encrypt value" }
  let(:des_encrypt_value) { "DES encrypt value" }

  it 'has a version number' do
    expect(OsslCryptor::VERSION).not_to be nil
  end

  it 'AES test all nil' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES)
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES test appoint pass' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES, nil, "test_pass")
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES test appoint pass and salt' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES, nil, "test_pass", "salt")
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES test appoint pass and salt and hash' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES, nil, "test_pass", "salt", "md5")
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES test appoint key_iv' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES, { key: '\xEEh\xE7!\xBB\xC79\x84\xF7\xDEGw;\x10P\xA4#\xBC\x90A\x05\xC3\xB8\b\x8A\e\x8D\x8A\xA9\xEA\x03K', iv: '\xD7hg\x16\xBB\r\x99S\e_\xF13\xE4KZ&' })
    enc_value = cryptor.encrypt(aes_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq aes_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq aes_encrypt_value
  end

  it 'AES test non base64' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::AES, { key: '\xEEh\xE7!\xBB\xC79\x84\xF7\xDEGw;\x10P\xA4#\xBC\x90A\x05\xC3\xB8\b\x8A\e\x8D\x8A\xA9\xEA\x03K', iv: '\xD7hg\x16\xBB\r\x99S\e_\xF13\xE4KZ&' })
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
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::DES, { key: '_\x13\xEBx\xF9\x14\xAAM', iv: '~\x14\x84\x00+4;.' })
    enc_value = cryptor.encrypt(des_encrypt_value)
    # puts enc_value
    expect(enc_value).not_to eq des_encrypt_value

    dec_value = cryptor.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq des_encrypt_value
  end

  it 'DES test non base64' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::DES, { key: '_\x13\xEBx\xF9\x14\xAAM', iv: '~\x14\x84\x00+4;.' })
    enc_value = cryptor.encrypt(des_encrypt_value, false)
    # puts enc_value
    expect(enc_value).not_to eq des_encrypt_value

    dec_value = cryptor.decrypt(enc_value, false)
    # puts dec_value
    expect(dec_value).to eq des_encrypt_value
  end

  it 'reset test' do
    cryptor = OsslCryptor::Cryptor.new(OsslCryptor::DES, { key: '_\x13\xEBx\xF9\x14\xAAM', iv: '~\x14\x84\x00+4;.' })
    cryptor.reset
    expect(true).to be_truthy
  end

  it 'available test' do
    available = OsslCryptor.available
    expect(available).to eq "#{OsslCryptor::AES}, #{OsslCryptor::DES}"
  end
end
