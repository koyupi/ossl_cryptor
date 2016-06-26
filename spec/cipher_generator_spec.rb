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
end
