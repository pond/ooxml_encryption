# frozen_string_literal: true

require 'ostruct'
require 'stringio'
require 'base64'
require 'openssl'

require 'simple_cfb'
require 'nokogiri'

# Ported from https://github.com/dtjohnson/xlsx-populate.
#
# Implements OOXML whole-file encryption and decryption.
#
# For low-level file format details, see:
# https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto.
#
class OoxmlEncryption

  # First 4 bytes are the version number, second 4 bytes are reserved.
  #
  ENCRYPTION_INFO_PREFIX        = [0x04, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00].pack('C*')
  PACKAGE_ENCRYPTION_CHUNK_SIZE = 4096

  # First 8 bytes are the size of the stream.
  #
  PACKAGE_OFFSET = 8

  # Block keys used for encryption.
  #
  BLOCK_KEYS = OpenStruct.new({
    dataIntegrity: OpenStruct.new({
      hmacKey:   [0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6].pack('C*'),
      hmacValue: [0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33].pack('C*')
    }),
    verifierHash: OpenStruct.new({
      input: [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79].pack('C*'),
      value: [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e].pack('C*')
    }),
    key: [0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6].pack('C*'),
  })

  # This aids testing to ensure that deterministic results are generated. The
  # performance overhead of a Proc is extremely low, especially compared to the
  # overhead of the encryption or decryption calculations.
  #
  RANDOM_BYTES_PROC = if ENV['RACK_ENV'] = 'test'
    -> (count) { '0' * count }
  else
    -> (count) { SecureRandom.random_bytes(count) }
  end

  # Convenience accessor to binary-encoded NUL byte.
  #
  NUL = String.new("\x00", encoding: 'ASCII-8BIT')

  # ===========================================================================
  # ENCRYPTION
  # ===========================================================================

  # Encrypt an unencrypted OOXML blob, returning the binary result. This is NOT
  # a streaming operation as the CFB format used to store the data is not
  # streamable itself - see the SimpleCfb gem for details.
  #
  # +unencrypted_spreadsheet_data+:: Unprotected OOXML input data as an
  #                                  ASCII-8BIT encoded string.
  #
  # +password+::                     Password for encryption in your choice of
  #                                  string encoding.
  #
  def encrypt(unencrypted_spreadsheet_data:, password:)

    # Generate a random key to use to encrypt the document. Excel uses 32 bytes. We'll use the password to encrypt this key.
    # N.B. The number of bits needs to correspond to an algorithm available in crypto (e.g. aes-256-cbc).
    #
    package_key = RANDOM_BYTES_PROC.call(32)

    # Create the encryption info. We'll use this for all of the encryption operations and for building the encryption info XML entry
    encryption_info = OpenStruct.new({
      package: OpenStruct.new({ # Info on the encryption of the package.
        cipherAlgorithm: 'AES', # Cipher algorithm to use. Excel uses AES.
        cipherChaining:  'ChainingModeCBC', # Cipher chaining mode to use. Excel uses CBC.
        saltValue:       RANDOM_BYTES_PROC.call(16), # Random value to use as encryption salt. Excel uses 16 bytes.
        hashAlgorithm:   'SHA512', # Hash algorithm to use. Excel uses SHA512.
        hashSize:        64, # The size of the hash in bytes. SHA512 results in 64-byte hashes
        blockSize:       16, # The number of bytes used to encrypt one block of data. It MUST be at least 2, no greater than 4096, and a multiple of 2. Excel uses 16
        keyBits:         package_key.size * 8 # The number of bits in the package key.
      }),
      key: OpenStruct.new({ # Info on the encryption of the package key.
        cipherAlgorithm: 'AES', # Cipher algorithm to use. Excel uses AES.
        cipherChaining:  'ChainingModeCBC', # Cipher chaining mode to use. Excel uses CBC.
        saltValue:       RANDOM_BYTES_PROC.call(16), # Random value to use as encryption salt. Excel uses 16 bytes.
        hashAlgorithm:   'SHA512', # Hash algorithm to use. Excel uses SHA512.
        hashSize:        64, # The size of the hash in bytes. SHA512 results in 64-byte hashes
        blockSize:       16, # The number of bytes used to encrypt one block of data. It MUST be at least 2, no greater than 4096, and a multiple of 2. Excel uses 16
        spinCount:       100000, # The number of times to iterate on a hash of a password. It MUST NOT be greater than 10,000,000. Excel uses 100,000.
        keyBits:         256 # The length of the key to generate from the password. Must be a multiple of 8. Excel uses 256.
      })
    })

    # =========================================================================
    # PACKAGE ENCRYPTION
    # =========================================================================

    # Encrypt package using the package key
    #
    encrypted_package = self.crypt_package(
      method:           :encrypt,
      cipher_algorithm: encryption_info.package.cipherAlgorithm,
      cipher_chaining:  encryption_info.package.cipherChaining,
      hash_algorithm:   encryption_info.package.hashAlgorithm,
      block_size:       encryption_info.package.blockSize,
      salt_value:       encryption_info.package.saltValue,
      key:              package_key,
      input:            unencrypted_spreadsheet_data
    )

    # =========================================================================
    # KEY ENCRYPTION
    # =========================================================================

    # Convert the password to an encryption key
    #
    key = self.convert_password_to_key(
      password,
      encryption_info.key.hashAlgorithm,
      encryption_info.key.saltValue,
      encryption_info.key.spinCount,
      encryption_info.key.keyBits,
      BLOCK_KEYS.key
    )

    # Encrypt the package key
    #
    encryption_info.key.encryptedKeyValue = self.crypt(
      method:           :encrypt,
      cipher_algorithm: encryption_info.key.cipherAlgorithm,
      cipher_chaining:  encryption_info.key.cipherChaining,
      key:              key,
      iv:               encryption_info.key.saltValue,
      input:            package_key
    )

    # =========================================================================
    # VERIFIER HASH
    # =========================================================================

    # Create a random byte array for hashing
    #
    verifier_hash_input = RANDOM_BYTES_PROC.call(16)

    # Create an encryption key from the password for the input
    #
    verifier_hash_input_key = self.convert_password_to_key(
      password,
      encryption_info.key.hashAlgorithm,
      encryption_info.key.saltValue,
      encryption_info.key.spinCount,
      encryption_info.key.keyBits,
      BLOCK_KEYS.verifierHash.input
    )

    # Use the key to encrypt the verifier input
    #
    encryption_info.key.encryptedVerifierHashInput = self.crypt(
      method:           :encrypt,
      cipher_algorithm: encryption_info.key.cipherAlgorithm,
      cipher_chaining:  encryption_info.key.cipherChaining,
      key:              verifier_hash_input_key,
      iv:               encryption_info.key.saltValue,
      input:            verifier_hash_input
    )

    # Create a hash of the input
    #
    verifier_hash_value = self.hash(
      encryption_info.key.hashAlgorithm,
      verifier_hash_input
    )

    # Create an encryption key from the password for the hash
    #
    verifier_hash_value_key = self.convert_password_to_key(
      password,
      encryption_info.key.hashAlgorithm,
      encryption_info.key.saltValue,
      encryption_info.key.spinCount,
      encryption_info.key.keyBits,
      BLOCK_KEYS.verifierHash.value
    )

    # Use the key to encrypt the hash value
    #
    encryption_info.key.encryptedVerifierHashValue = self.crypt(
      method:           :encrypt,
      cipher_algorithm: encryption_info.key.cipherAlgorithm,
      cipher_chaining:  encryption_info.key.cipherChaining,
      key:              verifier_hash_value_key,
      iv:               encryption_info.key.saltValue,
      input:            verifier_hash_value
    )

    # =========================================================================
    # DATA INTEGRITY
    # =========================================================================

    # Create the data integrity fields used by clients for integrity checks.
    #
    # First generate a random array of bytes to use in HMAC. The documentation
    # says that we should use the same length as the key salt, but Excel seems
    # to use 64.
    #
    hmac_key = RANDOM_BYTES_PROC.call(64)

    # Then create an initialization vector using the package encryption info
    # and the appropriate block key.
    #
    hmac_key_iv = self.create_iv(
      encryption_info.package.hashAlgorithm,
      encryption_info.package.saltValue,
      encryption_info.package.blockSize,
      BLOCK_KEYS.dataIntegrity.hmacKey
    )

    # Use the package key and the IV to encrypt the HMAC key
    #
    encrypted_hmac_key = self.crypt(
      method:           :encrypt,
      cipher_algorithm: encryption_info.package.cipherAlgorithm,
      cipher_chaining:  encryption_info.package.cipherChaining,
      key:              package_key,
      iv:               hmac_key_iv,
      input:            hmac_key
    )

    # Create the HMAC
    #
    hmac_value = self.hmac(
      encryption_info.package.hashAlgorithm,
      hmac_key,
      encrypted_package
    )

    # Generate an initialization vector for encrypting the resulting HMAC value
    #
    hmac_value_iv = self.create_iv(
      encryption_info.package.hashAlgorithm,
      encryption_info.package.saltValue,
      encryption_info.package.blockSize,
      BLOCK_KEYS.dataIntegrity.hmacValue
    )

    # Encrypt that value
    #
    encrypted_hmac_value = self.crypt(
      method:           :encrypt,
      cipher_algorithm: encryption_info.package.cipherAlgorithm,
      cipher_chaining:  encryption_info.package.cipherChaining,
      key:              package_key,
      iv:               hmac_value_iv,
      input:            hmac_value
    )

    # Add the encrypted key and value into the encryption info
    #
    encryption_info.dataIntegrity = OpenStruct.new({
      encryptedHmacKey:   encrypted_hmac_key,
      encryptedHmacValue: encrypted_hmac_value
    })

    # =========================================================================
    # OUTPUT
    # =========================================================================

    # Build the encryption info XML string
    #
    encryption_info = self.build_encryption_info(encryption_info)

    # Create a new CFB file
    #
    cfb = SimpleCfb.new

    # Add the encryption info and encrypted package
    #
    cfb.add('EncryptionInfo',   encryption_info  )
    cfb.add('EncryptedPackage', encrypted_package)

    # Compile and return the CFB file data
    #
    return cfb.write()
  end

  # ===========================================================================
  # DECRYPTION
  # ===========================================================================

  # Decrypt encrypted file data assumed to be the result of a prior encryption.
  # Returns the decrypted OOXML blob. This is NOT a streaming operation as the
  # underlying CFB file format used to store the data is not streamable itself;
  # see the SimpleCFB gem for details.
  #
  # +encrypted_spreadsheeet_data+:: Encrypted OOXML input data as an ASCII-8BIT
  #                                 encoded string.
  #
  # +password+::                    Password for decryption in your choice of
  #                                 string encoding.
  #
  def decrypt(encrypted_spreadsheeet_data:, password:)
    cfb = SimpleCfb.new
    cfb.parse!(StringIO.new(encrypted_spreadsheeet_data))

    encryption_info_xml        = cfb.file_index.find { |f| f.name == 'EncryptionInfo'   }&.content
    encrypted_spreadsheet_data = cfb.file_index.find { |f| f.name == 'EncryptedPackage' }&.content

    raise 'Cannot read file - corrupted or not encrypted?' if encryption_info_xml.nil? || encrypted_spreadsheet_data.nil?

    encryption_info_xml.delete_prefix!(ENCRYPTION_INFO_PREFIX)
    encryption_info = self.parse_encryption_info(encryption_info_xml)

    # Convert the password into an encryption key
    #
    key = self.convert_password_to_key(
      password,
      encryption_info.key.hashAlgorithm,
      encryption_info.key.saltValue,
      encryption_info.key.spinCount,
      encryption_info.key.keyBits,
      BLOCK_KEYS.key
    )

    # Use the key to decrypt the package key
    #
    package_key = self.crypt(
      method:           :decrypt,
      cipher_algorithm: encryption_info.key.cipherAlgorithm,
      cipher_chaining:  encryption_info.key.cipherChaining,
      key:              key,
      iv:               encryption_info.key.saltValue,
      input:            encryption_info.key.encryptedKeyValue
    )

    # Use the package key to decrypt the package
    #
    return self.crypt_package(
      method:           :decrypt,
      cipher_algorithm: encryption_info.package.cipherAlgorithm,
      cipher_chaining:  encryption_info.package.cipherChaining,
      hash_algorithm:   encryption_info.package.hashAlgorithm,
      block_size:       encryption_info.package.blockSize,
      salt_value:       encryption_info.package.saltValue,
      key:              package_key,
      input:            encrypted_spreadsheet_data
    )
  end

  # ===========================================================================
  # PRIVATE INSTANCE METHODS
  # ===========================================================================
  #
  private

    # Calculate a hash of the concatenated buffers with the given algorithm.
    # @param {string} algorithm - The hash algorithm.
    # @param {Array.<Buffer>} buffers - The buffers to concat and hash
    # @returns {Buffer} The hash
    #
    def hash(algorithm, *buffers)
      hash = Digest.const_get(algorithm).new

      buffers.each do | buffer |
        hash.update(buffer)
      end

      return hash.digest()
    end

    # Calculate an HMAC of the concatenated buffers with the given algorithm and key
    # @param {string} algorithm - The algorithm.
    # @param {string} key - The key
    # @param {Array.<Buffer>} buffers - The buffer to concat and HMAC
    # @returns {Buffer} The HMAC
    #
    def hmac(algorithm, key, *buffers)
      digest = OpenSSL::Digest.const_get(algorithm).new
      hmac   = OpenSSL::HMAC.new(key, digest)

      buffers.each do | buffer |
        hmac << buffer
      end

      return hmac.digest()
    end

    # Encrypt or decrypt input. Named parameters are:
    #
    # +method+::           Symbol :encrypt or :decrypt
    # +cipher_algorithm+:: Cipher algorithm
    # +cipher_chaining+::  Cipher chaining mode
    # +key+::              Encryption key
    # +iv+::               Initialization vector
    # +input+::            Input data
    #
    # Returns the result. Input and output values are all ASCII-8BIT encoded
    # Strings unless noted.
    #
    def crypt(
      method:,
      cipher_algorithm:,
      cipher_chaining:,
      key:,
      iv:,
      input:
    )
      cipher_name = "#{cipher_algorithm}-#{key.size * 8}-#{cipher_chaining.gsub("ChainingMode", "")}"
      cipher      = OpenSSL::Cipher.new(cipher_name).send(method)

      cipher.key     = key
      cipher.iv      = iv
      cipher.padding = 0 # JavaScript source sets auto-padding to 'false', so padding is manually managed

      return cipher.update(input) + cipher.final()
    end

    # Encrypt or decrypt an entire package. Named parameters are:
    #
    # +method+::           Symbol :encrypt or :decrypt
    # +cipher_algorithm+:: Cipher algorithm
    # +cipher_chaining+::  Cipher chaining mode
    # +hash_algorithm+::   Hash algorithm
    # +block_size+::       IV block size
    # +salt_value+::       Salt
    # +key+::              Encryption key
    # +input+::            Package data
    #
    # Returns the result. Input and output values are all ASCII-8BIT encoded
    # Strings unless noted.
    #
    def crypt_package(
      method:,
      cipher_algorithm:,
      cipher_chaining:,
      hash_algorithm:,
      block_size:,
      salt_value:,
      key:,
      input:
    )
      # The package is encoded in chunks. Encrypt/decrypt each and concat.
      #
      output = String.new(encoding: 'ASCII-8BIT')
      offset = method == :encrypt ? 0 : PACKAGE_OFFSET

      i = start = finish = 0

      while finish < input.bytesize
        start  = finish
        finish = start + PACKAGE_ENCRYPTION_CHUNK_SIZE
        finish = input.bytesize if finish > input.bytesize

        input_chunk = input[(start + offset)...(finish + offset)]

        # Pad the chunk if it is not an integer multiple of the block size
        #
        remainder = input_chunk.bytesize % block_size;

        if remainder > 0
          input_chunk << NUL * (block_size - remainder)
        end

        # Create the initialization vector
        #
        iv = self.create_iv(hash_algorithm, salt_value, block_size, i)

        # Encrypt the chunk and add it to the array
        #
        output << self.crypt(
          method:           method,
          cipher_algorithm: cipher_algorithm,
          cipher_chaining:  cipher_chaining,
          key:              key,
          iv:               iv,
          input:            input_chunk
        )

        i += 1
      end

      # Put the length of the package in the first 8 bytes if encrypting.
      # Truncate the data to the size in the prefix if decrypting.
      #
      if method == :encrypt
        length_data  = [input.bytesize].pack('V') # Unsigned 32-bit little-endian, bitwise truncated
        length_data << NUL * 4

        output.insert(0, length_data)
      else
        length = SimpleCfb.get_uint32le(input)
        output.slice!(length..) # (sic.)
      end

      return output;
    end

    # Convert a password into an encryption key
    # @param {string} password - The password
    # @param {string} hash_algorithm - The hash algoritm
    # @param {Buffer} salt_value - The salt value
    # @param {number} spin_count - The spin count
    # @param {number} key_bits - The length of the key in bits
    # @param {Buffer} block_key - The block key
    # @returns {Buffer} The encryption key
    #
    def convert_password_to_key(password, hash_algorithm, salt_value, spin_count, key_bits, block_key)

      # Password must little-endian UTF-16
      #
      password_buffer = password.encode('UTF-16LE').force_encoding('ASCII-8BIT')

      # Generate the initial hash
      #
      key = self.hash(hash_algorithm, salt_value, password_buffer)

      # Now regenerate until spin count
      #
      0.upto(spin_count - 1) do | i |
        iterator = [i].pack('V') # Unsigned 32-bit little-endian, bitwise truncated
        key      = self.hash(hash_algorithm, iterator, key)
      end

      # Now generate the final hash
      #
      key = self.hash(hash_algorithm, key, block_key)

      # Truncate or pad (with 0x36) as needed to get to length of key bits
      #
      key_bytes = key_bits / 8
      pad_byte  = String.new("\x36", encoding: 'ASCII-8BIT')

      if key.bytesize < key_bytes
        key = key.ljust(key_bytes, pad_byte)
      elsif key.bytesize > key_bytes
        key = key[0...key_bytes]
      end

      return key
    end

    # Create an initialization vector (IV)
    # @param {string} hash_algorithm - The hash algorithm
    # @param {Buffer} salt_value - The salt value
    # @param {number} block_size - The size of the IV
    # @param {Buffer|number} block_key - The block key or an int to convert to a buffer
    # @returns {Buffer} The IV
    #
    def create_iv(hash_algorithm, salt_value, block_size, block_key)
      unless block_key.is_a?(String) # (...then assume integer)
        block_key = [block_key].pack('V') # Unsigned 32-bit little-endian, bitwise truncated
      end

      # Create the initialization vector by hashing the salt with the block key.
      # Truncate or pad as needed to meet the block size.
      #
      iv       = self.hash(hash_algorithm, salt_value, block_key)
      pad_byte = String.new("\x36", encoding: 'ASCII-8BIT')

      if iv.bytesize < block_size
        iv = iv.ljust(block_size, pad_byte)
      elsif iv.bytesize > block_size
        iv = iv[0...block_size]
      end

      return iv
    end

    # Build the encryption info XML/buffer
    # @param {{}} encryption_info - The encryption info object
    # @returns {Buffer} The buffer
    #
    def build_encryption_info(encryption_info)

      # Map the object into the appropriate XML structure. Buffers are encoded in base 64.
      #
      preamble = Nokogiri::XML('<?xml version = "1.0" encoding="UTF-8" standalone="yes"?>')
      builder  = Nokogiri::XML::Builder.with(preamble) do |xml|
        xml.encryption({
          xmlns:     'http://schemas.microsoft.com/office/2006/encryption',
          'xmlns:p': 'http://schemas.microsoft.com/office/2006/keyEncryptor/password',
          'xmlns:c': 'http://schemas.microsoft.com/office/2006/keyEncryptor/certificate'
        }) do

          xml.keyData({
            saltSize:        encryption_info.package.saltValue.length,
            blockSize:       encryption_info.package.blockSize,
            keyBits:         encryption_info.package.keyBits,
            hashSize:        encryption_info.package.hashSize,
            cipherAlgorithm: encryption_info.package.cipherAlgorithm,
            cipherChaining:  encryption_info.package.cipherChaining,
            hashAlgorithm:   encryption_info.package.hashAlgorithm,
            saltValue:       Base64.strict_encode64(encryption_info.package.saltValue)
          })

          xml.dataIntegrity({
            encryptedHmacKey:   Base64.strict_encode64(encryption_info.dataIntegrity.encryptedHmacKey),
            encryptedHmacValue: Base64.strict_encode64(encryption_info.dataIntegrity.encryptedHmacValue)
          })

          xml.keyEncryptors do
            xml.keyEncryptor(uri: 'http://schemas.microsoft.com/office/2006/keyEncryptor/password') do
              xml.send('p:encryptedKey', {
                spinCount:                  encryption_info.key.spinCount,
                saltSize:                   encryption_info.key.saltValue.length,
                blockSize:                  encryption_info.key.blockSize,
                keyBits:                    encryption_info.key.keyBits,
                hashSize:                   encryption_info.key.hashSize,
                cipherAlgorithm:            encryption_info.key.cipherAlgorithm,
                cipherChaining:             encryption_info.key.cipherChaining,
                hashAlgorithm:              encryption_info.key.hashAlgorithm,
                saltValue:                  Base64.strict_encode64(encryption_info.key.saltValue),
                encryptedVerifierHashInput: Base64.strict_encode64(encryption_info.key.encryptedVerifierHashInput),
                encryptedVerifierHashValue: Base64.strict_encode64(encryption_info.key.encryptedVerifierHashValue),
                encryptedKeyValue:          Base64.strict_encode64(encryption_info.key.encryptedKeyValue)
              })
            end
          end
        end
      end

      xml_string = builder
        .to_xml(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML)
        .gsub("\n", '')
        .force_encoding('ASCII-8BIT')

      return ENCRYPTION_INFO_PREFIX + xml_string
    end

    # Pass a string containing raw encryption info data read from CFB input,
    # with prefix removed (so basically - pass an XML document).
    #
    # Returns the parsed result as nested OpenStructs.
    #
    def parse_encryption_info(encryption_info_xml)
      doc                 = Nokogiri.parse(encryption_info_xml, nil, 'UTF-8')
      key_data_node       = doc.css('keyData').first
      key_encryptors_node = doc.css('keyEncryptors').first
      key_encryptor_node  = key_encryptors_node.css('keyEncryptor').first
      encrypted_key_node  = key_encryptor_node.xpath('//p:encryptedKey').first

      return OpenStruct.new({
        package: OpenStruct.new({
            cipherAlgorithm: key_data_node.attributes['cipherAlgorithm'].value,
            cipherChaining:  key_data_node.attributes['cipherChaining'].value,
            saltValue:       Base64.decode64(key_data_node.attributes['saltValue'].value),
            hashAlgorithm:   key_data_node.attributes['hashAlgorithm'].value,
            blockSize:       key_data_node.attributes['blockSize'].value.to_i
        }),
        key: OpenStruct.new({
          encryptedKeyValue: Base64.decode64(encrypted_key_node.attributes['encryptedKeyValue'].value),
          cipherAlgorithm:   encrypted_key_node.attributes['cipherAlgorithm'].value,
          cipherChaining:    encrypted_key_node.attributes['cipherChaining'].value,
          saltValue:         Base64.decode64(encrypted_key_node.attributes['saltValue'].value),
          hashAlgorithm:     encrypted_key_node.attributes['hashAlgorithm'].value,
          spinCount:         encrypted_key_node.attributes['spinCount'].value.to_i,
          keyBits:           encrypted_key_node.attributes['keyBits'].value.to_i
        })
      })
    end

end # "class OoxmlEncryption"
