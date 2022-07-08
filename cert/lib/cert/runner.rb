require 'fileutils'
require 'fastlane_core/globals'
require 'fastlane_core/cert_checker'
require 'fastlane_core/print_table'
require 'spaceship'

require_relative 'module'

module Cert
  class Runner
    def launch
      run

      UI.success("Successfully installed certificate #{ENV['CER_CERTIFICATE_ID']}")
      return ENV["CER_FILE_PATH"]
    end

    def login
      if (api_token = Spaceship::ConnectAPI::Token.from(hash: Cert.config[:api_key], filepath: Cert.config[:api_key_path]))
        UI.message("Creating authorization token for App Store Connect API")
        Spaceship::ConnectAPI.token = api_token
      elsif !Spaceship::ConnectAPI.token.nil?
        UI.message("Using existing authorization token for App Store Connect API")
      else
        # Username is now optional since addition of App Store Connect API Key
        # Force asking for username to prompt user if not already set
        Cert.config.fetch(:username, force_ask: true)

        UI.message("Starting login with user '#{Cert.config[:username]}'")
        Spaceship::ConnectAPI.login(Cert.config[:username], nil, use_portal: true, use_tunes: false)
        UI.message("Successfully logged in")
      end
    end

    def run
      FileUtils.mkdir_p(Cert.config[:output_path])

      FastlaneCore::PrintTable.print_values(config: Cert.config, hide_keys: [:output_path], title: "Summary for cert #{Fastlane::VERSION}")

      login

      should_create = Cert.config[:force]
      unless should_create
        cert_path = find_existing_cert
        should_create = cert_path.nil?
      end

      return unless should_create

      if create_certificate # no certificate here, creating a new one
        return # success
      else
        UI.user_error!("Something went wrong when trying to create a new certificate...")
      end
    end

    # Command method for the :revoke_expired sub-command
    def revoke_expired_certs!
      FastlaneCore::PrintTable.print_values(config: Cert.config, hide_keys: [:output_path], title: "Summary for cert #{Fastlane::VERSION}")

      login

      to_revoke = expired_certs

      if to_revoke.empty?
        UI.success("No expired certificates were found to revoke! 👍")
        return
      end

      revoke_count = 0

      to_revoke.each do |certificate|
        begin
          UI.message("#{certificate.id} #{certificate.display_name} has expired, revoking...")
          certificate.delete!
          revoke_count += 1
        rescue => e
          UI.error("An error occurred while revoking #{certificate.id} #{certificate.display_name}")
          UI.error("#{e.message}\n#{e.backtrace.join("\n")}") if FastlaneCore::Globals.verbose?
        end
      end

      UI.success("#{revoke_count} expired certificate#{'s' if revoke_count != 1} #{revoke_count == 1 ? 'has' : 'have'} been revoked! 👍")
    end

    def expired_certs
      certificates.reject(&:valid?)
    end

    def find_existing_cert
      certificates.each do |certificate|
        unless certificate.certificate_content
          next
        end
        certificate_info = {
          name: certificate.name,
          expiration_date: certificate.expiration_date,
          valid: certificate.valid?,
          platform: certificate.platform,
          certificate_type: certificate.certificate_type
        }
        UI.message(certificate_info)
        path = store_certificate(certificate, Cert.config[:filename])
        UI.message("cert path:#{path}")
        ENV["CER_FILE_PATH"] = path
        private_key_path = File.expand_path(File.join(Cert.config[:output_path], "#{certificate.id}.p12"))
        ENV["PRIVATE_KEY_PATH"] = private_key_path
        return path
      end

      UI.important("Couldn't find an existing certificate... creating a new one")
      return nil
    end

    # All certificates of this type
    def certificates
      filter = {
        certificateType: certificate_type
      }
      return Spaceship::ConnectAPI::Certificate.all(filter: filter)
    end

    # The kind of certificate we're interested in
    def certificate_type
      if Cert.config[:type]
        case Cert.config[:type].to_sym
        when :mac_installer_distribution
          return Spaceship::ConnectAPI::Certificate::CertificateType::MAC_INSTALLER_DISTRIBUTION
        when :developer_id_application
          return Spaceship::ConnectAPI::Certificate::CertificateType::DEVELOPER_ID_APPLICATION
        when :developer_id_kext
          return Spaceship::ConnectAPI::Certificate::CertificateType::DEVELOPER_ID_KEXT
        when :developer_id_installer
          raise "Cannot do with ASC API?"
          # return Spaceship.certificate.developer_id_installer
        else
          UI.user_error("Unaccepted value for :type - #{Cert.config[:type]}")
        end
      end

      # Check if apple certs (Xcode 11 and later) should be used
      if Cert.config[:generate_apple_certs]
        cert_type = Spaceship::ConnectAPI::Certificate::CertificateType::DISTRIBUTION
        cert_type = Spaceship::ConnectAPI::Certificate::CertificateType::IOS_DISTRIBUTION if Spaceship::ConnectAPI.client.in_house? # Enterprise doesn't use Apple Distribution
        cert_type = Spaceship::ConnectAPI::Certificate::CertificateType::DEVELOPMENT if Cert.config[:development]
      else
        case Cert.config[:platform].to_s
        when 'ios', 'tvos'
          cert_type = Spaceship::ConnectAPI::Certificate::CertificateType::IOS_DISTRIBUTION
          cert_type = Spaceship::ConnectAPI::Certificate::CertificateType::IOS_DISTRIBUTION if Spaceship::ConnectAPI.client.in_house?
          cert_type = Spaceship::ConnectAPI::Certificate::CertificateType::IOS_DEVELOPMENT if Cert.config[:development]

        when 'macos'
          cert_type = Spaceship::ConnectAPI::Certificate::CertificateType::MAC_APP_DISTRIBUTION
          cert_type = Spaceship::ConnectAPI::Certificate::CertificateType::MAC_APP_DEVELOPMENT if Cert.config[:development]
        end
      end

      return cert_type
    end

    def create_certificate
      # Create a new certificate signing request
      csr, pkey = Spaceship::ConnectAPI::Certificate.create_certificate_signing_request

      # Use the signing request to create a new (development|distribution) certificate
      begin
        certificate = Spaceship::ConnectAPI::Certificate.create(
          certificate_type: certificate_type,
          csr_content: csr.to_pem
        )
      rescue => ex
        type_name = (Cert.config[:development] ? "Development" : "Distribution")
        if ex.to_s.include?("You already have a current")
          UI.user_error!("Could not create another #{type_name} certificate, reached the maximum number of available #{type_name} certificates.", show_github_issues: true)
        elsif ex.to_s.include?("You are not allowed to perform this operation.") && type_name == "Distribution"
          UI.user_error!("You do not have permission to create this certificate. Only Team Admins can create Distribution certificates\n 🔍 See https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/ManagingYourTeam/ManagingYourTeam.html for more information.")
        end
        raise ex
      end

      # Store all that onto the filesystem
      UI.verbose("Store cert onto the filesystem")
      UI.verbose(Cert.config)
      request_path = File.expand_path(File.join(Cert.config[:output_path], "#{certificate.id}.certSigningRequest"))
      File.write(request_path, csr.to_pem)
      UI.verbose("request_path:#{request_path}")

      private_key_path = File.expand_path(File.join(Cert.config[:output_path], "#{certificate.id}.p12"))
      File.write(private_key_path, pkey)
      UI.verbose("private_key_path:#{private_key_path}")

      cert_path = store_certificate(certificate, Cert.config[:filename])
      UI.verbose("cert_path:#{cert_path}")

      # Environment variables for the fastlane action
      ENV["CER_CERTIFICATE_ID"] = certificate.id
      ENV["CER_FILE_PATH"] = cert_path
      ENV["PRIVATE_KEY_PATH"] = private_key_path

      UI.success("Successfully generated #{certificate.id} which was imported to the local machine.")

      return cert_path
    end

    def store_certificate(certificate, filename = nil)
      cert_name = filename ? filename : certificate.id
      cert_name = "#{cert_name}.cer" unless File.extname(cert_name) == ".cer"
      path = File.expand_path(File.join(Cert.config[:output_path], cert_name))
      raw_data = Base64.decode64(certificate.certificate_content)
      File.write(path, raw_data.force_encoding("UTF-8"))
      return path
    end
  end
end
