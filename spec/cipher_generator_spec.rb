require 'spec_helper'

describe CipherGenerator do

  it 'generate AES test' do
    cipher = CipherGenerator.generate_cipher(OsslCryptor::AES)
    expect(cipher).to be_truthy
  end

  it 'generate DES test' do
    cipher = CipherGenerator.generate_cipher(OsslCryptor::DES)
    expect(cipher).to be_truthy
  end

  it 'generate AES random key and iv' do
    key_iv = CipherGenerator.generate_random_key_iv(OsslCryptor::AES)
    # p key_iv[:key]
    # p key_iv[:iv]
    expect(key_iv).to be_truthy
  end

  it 'generate DES random key and iv' do
    key_iv = CipherGenerator.generate_random_key_iv(OsslCryptor::DES)
    # p key_iv[:key]
    # p key_iv[:iv]
    expect(key_iv).to be_truthy
  end
end
