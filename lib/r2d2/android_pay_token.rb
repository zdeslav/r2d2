module R2D2
  class AndroidPayToken
    include Util

    attr_accessor :encrypted_message, :ephemeral_public_key, :tag

    def initialize(token_attrs)
      self.ephemeral_public_key = token_attrs["ephemeralPublicKey"]
      self.tag = token_attrs["tag"]
      self.encrypted_message = token_attrs["encryptedMessage"]
    end

    def decrypt(private_key_pem)
      private_key = OpenSSL::PKey::EC.new(private_key_pem)

      shared_secret = generate_shared_secret(private_key, ephemeral_public_key)

      # derive the symmetric_encryption_key and mac_key
      hkdf_keys = derive_hkdf_keys(ephemeral_public_key, shared_secret, 'Android')

      # verify the tag is a valid value
      verify_mac(hkdf_keys[:mac_key], encrypted_message, tag)

      JSON.parse(decrypt_message('ECv0', encrypted_message, hkdf_keys[:symmetric_encryption_key]))
    end
  end
end
