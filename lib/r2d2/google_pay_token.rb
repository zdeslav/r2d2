module R2D2
  class GooglePayToken
    include Util

    attr_reader :protocol_version, :recipient_id, :verification_keys, :signature, :signed_message, :signing_key, :signing_key_message, :key_signatures

    def initialize(token_attrs, recipient_id:, verification_keys:)
      @protocol_version = token_attrs['protocolVersion']
      @recipient_id = recipient_id
      @signature = token_attrs['signature']
      @signed_message = token_attrs['signedMessage']
      @verification_keys = filter_root_signing_keys(verification_keys['keys'], @protocol_version)
      if @protocol_version == 'ECv2'
        @signing_key_message = token_attrs['intermediateSigningKey']['signedKey']
        @key_signatures = token_attrs['intermediateSigningKey']['signatures']
      end
    end

    def decrypt(private_key_pem)
      raise KeysUnavailableError if verification_keys.empty?

      verify_signing_key if protocol_version == 'ECv2'
      verified = verify_and_parse_message

      private_key = OpenSSL::PKey::EC.new(private_key_pem)
      shared_secret = generate_shared_secret(private_key, verified['ephemeralPublicKey'])
      hkdf_keys = derive_hkdf_keys(verified['ephemeralPublicKey'], shared_secret, 'Google', protocol_version)

      verify_mac(hkdf_keys[:mac_key], verified['encryptedMessage'], verified['tag'])
      decrypted = JSON.parse(
        decrypt_message(protocol_version, verified['encryptedMessage'], hkdf_keys[:symmetric_encryption_key])
      )

      expired = decrypted['messageExpiration'].to_f / 1000.0 <= Time.now.to_f
      raise MessageExpiredError if expired

      decrypted
    end

    private

    def filter_root_signing_keys(keys, protocol)
      keys
        .select {|key| key['protocolVersion'] == protocol && (key['keyExpiration'] == nil || key['keyExpiration'].to_f / 1000.0 > Time.now.to_f)  }
        .map {|key| key['keyValue'] }
    end

    def verify_signing_key
      digest = OpenSSL::Digest::SHA256.new
      signed_bytes = to_length_value('Google', protocol_version, signing_key_message)

      verified = verification_keys.any? do |key|
        ec = OpenSSL::PKey::EC.new(Base64.strict_decode64(key))
        key_signatures.any? do |key_signature|
          ec.verify(digest, Base64.strict_decode64(key_signature), signed_bytes)
        end
      end

      if verified
        key_data = JSON.parse(signing_key_message)
        expired = key_data['keyExpiration'].to_f / 1000.0 <= Time.now.to_f
        raise KeyExpiredError if expired
        @verification_keys = [key_data['keyValue']]
      else
        raise KeySignatureInvalidError
      end
    end

    def verify_and_parse_message
      digest = OpenSSL::Digest::SHA256.new
      signed_bytes = to_length_value('Google', recipient_id, protocol_version, signed_message)

      verified = verification_keys.any? do |key|
        ec = OpenSSL::PKey::EC.new(Base64.strict_decode64(key))
        ec.verify(digest, Base64.strict_decode64(signature), signed_bytes)
      end

      raise SignatureInvalidError unless verified
      JSON.parse(signed_message)
    end
  end
end
