require 'spec_helper'

describe OsslCryptor do

  it 'generate AES-128-CBC test' do
    cipher = OsslCryptor::Generator.generate_cipher(OsslCryptor::AES_128)
    expect(cipher).to be_truthy
  end

  it 'generate AES-256-CBC test' do
    cipher = OsslCryptor::Generator.generate_cipher(OsslCryptor::AES_256)
    expect(cipher).to be_truthy
  end

  it 'generate DES test' do
    cipher = OsslCryptor::Generator.generate_cipher(OsslCryptor::DES)
    expect(cipher).to be_truthy
  end

  it 'generate AES-128-CBC random key and iv' do
    key_iv = OsslCryptor::Generator.generate_random_key_iv(OsslCryptor::AES_128)
    # p key_iv[:key]
    # p key_iv[:iv]
    expect(key_iv).to be_truthy
  end

  it 'generate AES-256-CBC random key and iv' do
    key_iv = OsslCryptor::Generator.generate_random_key_iv(OsslCryptor::AES_256)
    # p key_iv[:key]
    # p key_iv[:iv]
    expect(key_iv).to be_truthy
  end

  it 'generate DES random key and iv' do
    key_iv = OsslCryptor::Generator.generate_random_key_iv(OsslCryptor::DES)
    # p key_iv[:key]
    # p key_iv[:iv]
    expect(key_iv).to be_truthy
  end
end
