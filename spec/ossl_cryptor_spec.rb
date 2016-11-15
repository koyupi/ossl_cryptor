require 'spec_helper'

describe OsslCryptor do

  it 'has a version number' do
    expect(OsslCryptor::VERSION).not_to be nil
  end

  it 'available test' do
    available = OsslCryptor.available
    expect(available).to eq "#{OsslCryptor::AES_128}, #{OsslCryptor::AES_256}, #{OsslCryptor::DES}"
  end
end
