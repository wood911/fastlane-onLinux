describe Fastlane do
  describe Fastlane::FastFile do
    describe "adb" do
      it "calls AdbHelper to trigger command" do
        expect_any_instance_of(Fastlane::Helper::AdbHelper)
          .to receive(:trigger)
          .with(command: "fake command", serial: "fake serial")
          .and_return("some stub adb response")

        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'fake command', serial: 'fake serial')
        end").runner.execute(:test)

        expect(result).to eq("some stub adb response")
      end
    end

    describe "adb on non windows" do
      before(:each) do
        allow(FastlaneCore::Helper).to receive(:windows?).and_return(false)
      end

      it "generates a valid command" do
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test', adb_path: './README.md')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('./fastlane/README.md')} test")
      end

      it "generates a valid command for commands with multiple parts" do
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test command with multiple parts', adb_path: './README.md')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('./fastlane/README.md')} test command with multiple parts")
      end

      it "generates a valid command when a non-empty serial is passed" do
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test command with non-empty serial', adb_path: './README.md', serial: 'emulator-1234')
        end").runner.execute(:test)

        expect(result).to eq("ANDROID_SERIAL=emulator-1234 #{File.expand_path('./fastlane/README.md')} test command with non-empty serial")
      end

      it "generates a valid command when an empty serial is passed" do
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test command with empty serial', adb_path: './README.md', serial: '')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('./fastlane/README.md')} test command with empty serial")
      end

      it "picks up path from ANDROID_HOME environment variable" do
        stub_const('ENV', { 'ANDROID_HOME' => '/usr/local/android-sdk' })
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('/usr/local/android-sdk/platform-tools/adb')} test")
      end

      it "picks up path from ANDROID_HOME environment variable and handles path that has to be made safe" do
        stub_const('ENV', { 'ANDROID_HOME' => '/usr/local/android-sdk/with space' })
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test')
        end").runner.execute(:test)

        path = File.expand_path("/usr/local/android-sdk/with space/platform-tools/adb").shellescape
        expect(result).to eq("#{path} test")
      end

      it "picks up path from ANDROID_SDK_ROOT environment variable" do
        stub_const('ENV', { 'ANDROID_SDK_ROOT' => '/usr/local/android-sdk' })
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('/usr/local/android-sdk/platform-tools/adb')} test")
      end

      it "picks up path from ANDROID_SDK environment variable" do
        stub_const('ENV', { 'ANDROID_SDK' => '/usr/local/android-sdk' })
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('/usr/local/android-sdk/platform-tools/adb')} test")
      end
    end

    describe "adb on Windows" do
      before(:each) do
        allow(FastlaneCore::Helper).to receive(:windows?).and_return(true)
      end

      it "generates a valid command" do
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test', adb_path: './README.md')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('./fastlane/README.md').gsub('/', '\\')} test")
      end

      it "generates a valid command for commands with multiple parts" do
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test command with multiple parts', adb_path: './README.md')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('./fastlane/README.md').gsub('/', '\\')} test command with multiple parts")
      end

      it "generates a valid command when a non-empty serial is passed" do
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test command with non-empty serial', adb_path: './README.md', serial: 'emulator-1234')
        end").runner.execute(:test)

        expect(result).to eq("ANDROID_SERIAL=emulator-1234 #{File.expand_path('./fastlane/README.md').gsub('/', '\\')} test command with non-empty serial")
      end

      it "generates a valid command when an empty serial is passed" do
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test command with empty serial', adb_path: './README.md', serial: '')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('./fastlane/README.md').gsub('/', '\\')} test command with empty serial")
      end

      it "picks up path from ANDROID_HOME environment variable" do
        stub_const('ENV', { 'ANDROID_HOME' => '/Users\\SomeUser\\AppData\\Local\\Android\\Sdk' })
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('/Users\\SomeUser\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb').gsub('/', '\\')} test")
      end

      it "picks up path from ANDROID_HOME environment variable and handles path that has to be made safe" do
        stub_const('ENV', { 'ANDROID_HOME' => '/Users\\Some User With Space\\AppData\\Local\\Android\\Sdk' })
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test')
        end").runner.execute(:test)

        path = File.expand_path("/Users\\Some User With Space\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb").shellescape.gsub('/', '\\')
        expect(result).to eq("#{path} test")
      end

      it "picks up path from ANDROID_SDK_ROOT environment variable" do
        stub_const('ENV', { 'ANDROID_SDK_ROOT' => '/Users\\SomeUser\\AppData\\Local\\Android\\Sdk' })
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('/Users\\SomeUser\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb').gsub('/', '\\')} test")
      end

      it "picks up path from ANDROID_SDK environment variable" do
        stub_const('ENV', { 'ANDROID_SDK' => '/Users\\SomeUser\\AppData\\Local\\Android\\Sdk' })
        result = Fastlane::FastFile.new.parse("lane :test do
          adb(command: 'test')
        end").runner.execute(:test)

        expect(result).to eq("#{File.expand_path('/Users\\SomeUser\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb').gsub('/', '\\')} test")
      end
    end
  end
end
