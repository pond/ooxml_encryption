require 'spec_helper'

RSpec.describe OoxmlEncryption do

  # In test mode, all normally-random values are set to fixed strings. The
  # Node-based JavaScript code was set to do the same and asked to encrypt
  # the same spreadsheet. We therefore expect absolutely byte-identical
  # results.
  #
  context 'end-to-end encryption' do
    it 'generates the same data as its JavaScript counterpart' do
      input_xlsx  = File.open(File.join(__dir__, '..', 'fixtures',    'unencrypted_spreadsheet.xlsx'), 'rb') { | file | file.read() }
      node_output = File.open(File.join(__dir__, '..', 'fixtures', 'node_encrypted_spreadsheet.xlsx'), 'rb') { | file | file.read() }

      encryptor = described_class.new
      encrypted = encryptor.encrypt(
        unencrypted_spreadsheet_data: input_xlsx,
        password:                     'secret'
      )

      expect(encrypted).to match(node_output)
    end
  end # "context 'end-to-end encryption' do"

  context 'end-to-end decryption' do
    it 'generates the same data as its JavaScript counterpart' do
      input_enc_xlsx    = File.open(File.join(__dir__, '..', 'fixtures', 'node_encrypted_spreadsheet.xlsx'), 'rb') { | file | file.read() }
      node_unenc_output = File.open(File.join(__dir__, '..', 'fixtures',    'unencrypted_spreadsheet.xlsx'), 'rb') { | file | file.read() }

      encryptor = described_class.new
      decrypted = encryptor.decrypt(
        encrypted_spreadsheet_data: input_enc_xlsx,
        password:                   'secret'
      )

      expect(decrypted).to match(node_unenc_output)
    end
  end # "context 'end-to-end decryption' do"
end
