require 'fastlane_core/keychain_importer'
require 'openssl'
require_relative 'module'

module Match
  class Utils
    def self.import(item_path, keychain, password: nil)
      keychain_path = FastlaneCore::Helper.keychain_path(keychain)
      FastlaneCore::KeychainImporter.import_file(item_path, keychain_path, keychain_password: password, output: FastlaneCore::Globals.verbose?)
    end

    # Fill in an environment variable, ready to be used in _xcodebuild_
    def self.fill_environment(key, value)
      UI.important("Setting environment variable '#{key}' to '#{value}'") if FastlaneCore::Globals.verbose?
      ENV[key] = value
    end

    def self.environment_variable_name(app_identifier: nil, type: nil, platform: :ios)
      base_environment_variable_name(app_identifier: app_identifier, type: type, platform: platform).join("_")
    end

    def self.environment_variable_name_team_id(app_identifier: nil, type: nil, platform: :ios)
      (base_environment_variable_name(app_identifier: app_identifier, type: type, platform: platform) + ["team-id"]).join("_")
    end

    def self.environment_variable_name_profile_name(app_identifier: nil, type: nil, platform: :ios)
      (base_environment_variable_name(app_identifier: app_identifier, type: type, platform: platform) + ["profile-name"]).join("_")
    end

    def self.environment_variable_name_profile_path(app_identifier: nil, type: nil, platform: :ios)
      (base_environment_variable_name(app_identifier: app_identifier, type: type, platform: platform) + ["profile-path"]).join("_")
    end

    def self.get_cert_info(cer_certificate_path)
      cert = OpenSSL::X509::Certificate.new(File.binread(cer_certificate_path))

      # openssl output:
      # subject= /UID={User ID}/CN={Certificate Name}/OU={Certificate User}/O={Organisation}/C={Country}
      cert_info = cert.subject.to_s.gsub(/\s*subject=\s*/, "").tr("/", "\n")
      out_array = cert_info.split("\n")
      openssl_keys_to_readable_keys = {
           'UID' => 'User ID',
           'CN' => 'Common Name',
           'OU' => 'Organisation Unit',
           'O' => 'Organisation',
           'C' => 'Country',
           'notBefore' => 'Start Datetime',
           'notAfter' => 'End Datetime'
       }

      return out_array.map { |x| x.split(/=+/) if x.include?("=") }
                      .compact
                      .map { |k, v| [openssl_keys_to_readable_keys.fetch(k, k), v] }
                      .push([openssl_keys_to_readable_keys.fetch("notBefore"), cert.not_before])
                      .push([openssl_keys_to_readable_keys.fetch("notAfter"), cert.not_after])
    rescue => ex
      UI.error("get_cert_info: #{ex}")
      return {}
    end

    def self.error_callback(code, msg)
      url = ENV["ERROR_CALLBACK_URL"].to_s
      UI.verbose("error_callback:#{url}")
      unless url.empty?
        uri = URI.parse(url)
        req = Net::HTTP::Post.new(uri.path, { 'Content-Type' => 'application/json' })
        req.body = {code: code, msg: msg}.to_json
        UI.verbose("====body===")
        UI.verbose(req.body)
        http = Net::HTTP.new(uri.host, uri.port)
        response = http.request(req)
        UI.verbose(response)
      end
    end

    def self.profile_callback(params)
      url = ENV["PROFILE_CALLBACK_URL"].to_s
      UI.verbose("profile_callback:#{url}")
      unless url.empty?
        uri = URI.parse(url)
        req = Net::HTTP::Post.new(uri.path, { 'Content-Type' => 'application/json' })
        req.body = params.to_json
        UI.verbose("====body===")
        UI.verbose(req.body)
        http = Net::HTTP.new(uri.host, uri.port)
        response = http.request(req)
        UI.verbose(response)
      end
    end

    def self.cert_revoke_callback(params)
      url = ENV["CERT_REVOKE_CALLBACK_URL"].to_s
      UI.verbose("cert_revoke_callback:#{url}")
      unless url.empty?
        hash = eval(ENV["FL_RESIGN_PARAMS"])
        hash[:cert_info] = params
        uri = URI.parse(url)
        req = Net::HTTP::Post.new(uri.path, { 'Content-Type' => 'application/json' })
        req.body = hash.to_json
        UI.verbose("====body===")
        UI.verbose(req.body)
        http = Net::HTTP.new(uri.host, uri.port)
        response = http.request(req)
        UI.verbose(response)
      end
    end

    def self.is_cert_valid?(cer_certificate_path)
      cert = OpenSSL::X509::Certificate.new(File.binread(cer_certificate_path))
      now = Time.now.utc
      return (now <=> cert.not_after) == -1
    end

    def self.base_environment_variable_name(app_identifier: nil, type: nil, platform: :ios)
      if platform.to_s == :ios.to_s
        ["sigh", app_identifier, type] # We keep the ios profiles without the platform for backwards compatibility
      else
        ["sigh", app_identifier, type, platform.to_s]
      end
    end
  end
end
