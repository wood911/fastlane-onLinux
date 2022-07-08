describe Fastlane do
  describe Fastlane::FastFile do
    describe "Setup Jenkins Integration" do
      before :each do
        # Clean all used environment variables
        Fastlane::Actions::SetupJenkinsAction::USED_ENV_NAMES + Fastlane::Actions::SetupJenkinsAction.available_options.map(&:env_name).each do |key|
          ENV.delete(key)
        end
      end

      it "doesn't work outside CI" do
        stub_const("ENV", {})

        expect(UI).to receive(:important).with("Not executed by Continuous Integration system.")

        Fastlane::FastFile.new.parse("lane :test do
          setup_jenkins
        end").runner.execute(:test)

        expect(ENV["BACKUP_XCARCHIVE_DESTINATION"]).to be_nil
        expect(ENV["DERIVED_DATA_PATH"]).to be_nil
        expect(ENV["FL_CARTHAGE_DERIVED_DATA"]).to be_nil
        expect(ENV["FL_SLATHER_BUILD_DIRECTORY"]).to be_nil
        expect(ENV["GYM_BUILD_PATH"]).to be_nil
        expect(ENV["GYM_CODE_SIGNING_IDENTITY"]).to be_nil
        expect(ENV["GYM_DERIVED_DATA_PATH"]).to be_nil
        expect(ENV["GYM_OUTPUT_DIRECTORY"]).to be_nil
        expect(ENV["GYM_RESULT_BUNDLE"]).to be_nil
        expect(ENV["SCAN_DERIVED_DATA_PATH"]).to be_nil
        expect(ENV["SCAN_OUTPUT_DIRECTORY"]).to be_nil
        expect(ENV["SCAN_RESULT_BUNDLE"]).to be_nil
        expect(ENV["XCODE_DERIVED_DATA_PATH"]).to be_nil
        expect(ENV["MATCH_KEYCHAIN_NAME"]).to be_nil
        expect(ENV["MATCH_KEYCHAIN_PASSWORD"]).to be_nil
        expect(ENV["MATCH_READONLY"]).to be_nil
      end

      it "works when forced" do
        allow(FastlaneCore::FastlaneFolder).to receive(:path).and_return(nil)
        stub_const("ENV", {})

        Fastlane::FastFile.new.parse("lane :test do
          setup_jenkins(
            force: true
          )
        end").runner.execute(:test)

        pwd = Dir.pwd
        output = File.expand_path(File.join(pwd, "./output"))
        derived_data = File.expand_path(File.join(pwd, "./derivedData"))
        expect(ENV["BACKUP_XCARCHIVE_DESTINATION"]).to eq(output)
        expect(ENV["DERIVED_DATA_PATH"]).to eq(derived_data)
        expect(ENV["FL_CARTHAGE_DERIVED_DATA"]).to eq(derived_data)
        expect(ENV["FL_SLATHER_BUILD_DIRECTORY"]).to eq(derived_data)
        expect(ENV["GYM_BUILD_PATH"]).to eq(output)
        expect(ENV["GYM_CODE_SIGNING_IDENTITY"]).to be_nil
        expect(ENV["GYM_DERIVED_DATA_PATH"]).to eq(derived_data)
        expect(ENV["GYM_OUTPUT_DIRECTORY"]).to eq(output)
        expect(ENV["GYM_RESULT_BUNDLE"]).to eq("YES")
        expect(ENV["SCAN_DERIVED_DATA_PATH"]).to eq(derived_data)
        expect(ENV["SCAN_OUTPUT_DIRECTORY"]).to eq(output)
        expect(ENV["SCAN_RESULT_BUNDLE"]).to eq("YES")
        expect(ENV["XCODE_DERIVED_DATA_PATH"]).to eq(derived_data)
      end

      it "works inside CI" do
        allow(FastlaneCore::FastlaneFolder).to receive(:path).and_return(nil)
        stub_const("ENV", { "JENKINS_URL" => "123" })

        Fastlane::FastFile.new.parse("lane :test do
          setup_jenkins
        end").runner.execute(:test)

        pwd = Dir.pwd
        output = File.expand_path(File.join(pwd, "output"))
        derived_data = File.expand_path(File.join(pwd, "derivedData"))
        expect(ENV["BACKUP_XCARCHIVE_DESTINATION"]).to eq(output)
        expect(ENV["DERIVED_DATA_PATH"]).to eq(derived_data)
        expect(ENV["FL_CARTHAGE_DERIVED_DATA"]).to eq(derived_data)
        expect(ENV["FL_SLATHER_BUILD_DIRECTORY"]).to eq(derived_data)
        expect(ENV["GYM_BUILD_PATH"]).to eq(output)
        expect(ENV["GYM_CODE_SIGNING_IDENTITY"]).to be_nil
        expect(ENV["GYM_DERIVED_DATA_PATH"]).to eq(derived_data)
        expect(ENV["GYM_OUTPUT_DIRECTORY"]).to eq(output)
        expect(ENV["GYM_RESULT_BUNDLE"]).to eq("YES")
        expect(ENV["SCAN_DERIVED_DATA_PATH"]).to eq(derived_data)
        expect(ENV["SCAN_OUTPUT_DIRECTORY"]).to eq(output)
        expect(ENV["SCAN_RESULT_BUNDLE"]).to eq("YES")
        expect(ENV["XCODE_DERIVED_DATA_PATH"]).to eq(derived_data)
      end

      describe "under CI" do
        before :each do
          stub_const("ENV", { "JENKINS_URL" => "123" })
        end

        it "disable keychain unlock" do
          keychain_path = Tempfile.new("foo").path
          ENV["KEYCHAIN_PATH"] = keychain_path

          expect(UI).to receive(:message).with(/Set output directory path to:/)
          expect(UI).to receive(:message).with(/Set derived data path to:/)
          expect(UI).to receive(:message).with("Set result bundle.")

          Fastlane::FastFile.new.parse("lane :test do
            setup_jenkins(
              unlock_keychain: false
            )
          end").runner.execute(:test)

          expect(ENV["MATCH_KEYCHAIN_NAME"]).to be_nil
          expect(ENV["MATCH_KEYCHAIN_PASSWORD"]).to be_nil
          expect(ENV["MATCH_READONLY"]).to be_nil
        end

        it "unlock keychain" do
          allow(Fastlane::Actions::UnlockKeychainAction).to receive(:run).and_return(nil)

          keychain_path = Tempfile.new("foo").path
          ENV["KEYCHAIN_PATH"] = keychain_path

          expect(UI).to receive(:message).with("Unlocking keychain: \"#{keychain_path}\".")
          expect(UI).to receive(:message).with(/Set output directory path to:/)
          expect(UI).to receive(:message).with(/Set derived data path to:/)
          expect(UI).to receive(:message).with("Set result bundle.")

          Fastlane::FastFile.new.parse("lane :test do
            setup_jenkins(
              keychain_password: 'password'
            )
          end").runner.execute(:test)

          expect(ENV["MATCH_KEYCHAIN_NAME"]).to eq(keychain_path)
          expect(ENV["MATCH_KEYCHAIN_PASSWORD"]).to eq("password")
          expect(ENV["MATCH_READONLY"]).to eq("true")
        end

        it "does not setup match if previously set" do
          ENV["MATCH_KEYCHAIN_NAME"] = keychain_name = "keychain_name"
          ENV["MATCH_KEYCHAIN_PASSWORD"] = keychain_password = "keychain_password"
          ENV["MATCH_READONLY"] = "false"

          Fastlane::FastFile.new.parse("lane :test do
            setup_jenkins
          end").runner.execute(:test)

          expect(ENV["MATCH_KEYCHAIN_NAME"]).to eq(keychain_name)
          expect(ENV["MATCH_KEYCHAIN_PASSWORD"]).to eq(keychain_password)
          expect(ENV["MATCH_READONLY"]).to eq("false")
        end

        it "set code signing identity" do
          ENV["CODE_SIGNING_IDENTITY"] = "Code signing"

          Fastlane::FastFile.new.parse("lane :test do
            setup_jenkins
          end").runner.execute(:test)

          expect(ENV["GYM_CODE_SIGNING_IDENTITY"]).to eq("Code signing")
        end

        it "disable setting code signing identity" do
          ENV["CODE_SIGNING_IDENTITY"] = "Code signing"

          Fastlane::FastFile.new.parse("lane :test do
            setup_jenkins(
              set_code_signing_identity: false
            )
          end").runner.execute(:test)

          expect(ENV["GYM_CODE_SIGNING_IDENTITY"]).to be_nil
        end

        it "set output directory" do
          tmp_path = Dir.mktmpdir
          directory = "#{tmp_path}/output/directory"
          Fastlane::FastFile.new.parse("lane :test do
            setup_jenkins(
              output_directory: '#{directory}'
            )
          end").runner.execute(:test)

          expect(ENV["BACKUP_XCARCHIVE_DESTINATION"]).to eq(directory)
          expect(ENV["GYM_BUILD_PATH"]).to eq(directory)
          expect(ENV["GYM_OUTPUT_DIRECTORY"]).to eq(directory)
          expect(ENV["SCAN_OUTPUT_DIRECTORY"]).to eq(directory)
        end

        it "set derived data" do
          tmp_path = Dir.mktmpdir
          directory = "#{tmp_path}/derived_data"
          Fastlane::FastFile.new.parse("lane :test do
            setup_jenkins(
              derived_data_path: '#{directory}'
            )
          end").runner.execute(:test)

          expect(ENV["DERIVED_DATA_PATH"]).to eq(directory)
          expect(ENV["FL_CARTHAGE_DERIVED_DATA"]).to eq(directory)
          expect(ENV["FL_SLATHER_BUILD_DIRECTORY"]).to eq(directory)
          expect(ENV["GYM_DERIVED_DATA_PATH"]).to eq(directory)
          expect(ENV["SCAN_DERIVED_DATA_PATH"]).to eq(directory)
          expect(ENV["XCODE_DERIVED_DATA_PATH"]).to eq(directory)
        end

        it "disable result bundle path" do
          Fastlane::FastFile.new.parse("lane :test do
            setup_jenkins(
              result_bundle: false
            )
          end").runner.execute(:test)

          expect(ENV["GYM_RESULT_BUNDLE"]).to be_nil
          expect(ENV["SCAN_RESULT_BUNDLE"]).to be_nil
        end
      end

      after :all do
        # Clean all used environment variables
        Fastlane::Actions::SetupJenkinsAction::USED_ENV_NAMES + Fastlane::Actions::SetupJenkinsAction.available_options.map(&:env_name).each do |key|
          ENV.delete(key)
        end
      end
    end
  end
end
