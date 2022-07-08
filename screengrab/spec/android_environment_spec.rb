describe Screengrab do
  describe Screengrab::AndroidEnvironment do
    before(:each) do
      allow(FastlaneCore::Helper).to receive(:windows?).and_return(false)
    end

    describe "with an empty ANDROID_HOME and an empty PATH" do
      it "finds no useful values" do
        FastlaneSpec::Env.with_env_values('PATH' => 'screengrab/spec/fixtures/empty_home_empty_path/path') do
          android_env = Screengrab::AndroidEnvironment.new('screengrab/spec/fixtures/empty_home_empty_path/android_home')

          expect(android_env.android_home).to eq('screengrab/spec/fixtures/empty_home_empty_path/android_home')
          expect(android_env.platform_tools_path).to be_nil
          expect(android_env.adb_path).to be_nil
        end
      end
    end

    describe "with an empty ANDROID_HOME and a complete PATH" do
      it "finds commands on the PATH" do
        FastlaneSpec::Env.with_env_values('PATH' => 'screengrab/spec/fixtures/empty_home_complete_path/path') do
          android_env = Screengrab::AndroidEnvironment.new('screengrab/spec/fixtures/empty_home_complete_path/android_home')

          expect(android_env.android_home).to eq('screengrab/spec/fixtures/empty_home_complete_path/android_home')
          expect(android_env.platform_tools_path).to be_nil
          expect(android_env.adb_path).to eq('screengrab/spec/fixtures/empty_home_complete_path/path/adb')
        end
      end
    end

    describe "with a complete ANDROID_HOME and a complete PATH" do
      it "finds adb in platform-tools" do
        FastlaneSpec::Env.with_env_values('PATH' => 'screengrab/spec/fixtures/complete_home_complete_path/path') do
          android_env = Screengrab::AndroidEnvironment.new('screengrab/spec/fixtures/complete_home_complete_path/android_home')

          expect(android_env.android_home).to eq('screengrab/spec/fixtures/complete_home_complete_path/android_home')
          expect(android_env.platform_tools_path).to eq('screengrab/spec/fixtures/complete_home_complete_path/android_home/platform-tools')
          expect(android_env.adb_path).to eq('screengrab/spec/fixtures/complete_home_complete_path/android_home/platform-tools/adb')
        end
      end
    end
  end

  describe "on windows", if: FastlaneCore::Helper.windows? do
    describe "with an empty ANDROID_HOME and a complete PATH" do
      it "finds commands on the PATH" do
        FastlaneSpec::Env.with_env_values('PATH' => 'screengrab\\spec\\fixtures\\empty_home_complete_path_windows\\path', 'PATHEXT' => ".EXE") do
          android_env = Screengrab::AndroidEnvironment.new('screengrab\\spec\\fixtures\\empty_home_complete_path_windows\\android_home', nil)

          expect(android_env.android_home).to eq('screengrab\\spec\\fixtures\\empty_home_complete_path_windows\\android_home')
          expect(android_env.platform_tools_path).to be_nil
          expect(android_env.adb_path).to eq('screengrab\\spec\\fixtures\\empty_home_complete_path_windows\\path\\adb.exe')
        end
      end
    end

    describe "with a complete ANDROID_HOME and a complete PATH and no build tools version specified" do
      it "finds adb.exe in platform-tools and aapt in the highest version build tools dir" do
        FastlaneSpec::Env.with_env_values('PATH' => 'screengrab\\spec\\fixtures\\complete_home_complete_path_windows\\path', 'PATHEXT' => ".EXE") do
          android_env = Screengrab::AndroidEnvironment.new('screengrab\\spec\\fixtures\\complete_home_complete_path_windows\\android_home', nil)

          expect(android_env.android_home).to eq('screengrab\\spec\\fixtures\\complete_home_complete_path_windows\\android_home')
          expect(android_env.platform_tools_path).to eq('screengrab\\spec\\fixtures\\complete_home_complete_path_windows\\android_home\\platform-tools')
          expect(android_env.adb_path).to eq('screengrab\\spec\\fixtures\\complete_home_complete_path_windows\\android_home\\platform-tools\\adb.exe')
        end
      end
    end

    describe "with a complete ANDROID_HOME and a complete PATH and no build tools version specified" do
      it "finds adb in platform-tools and aapt in the highest version build tools dir" do
        FastlaneSpec::Env.with_env_values('PATH' => 'screengrab\\spec\\fixtures\\complete_home_complete_path_windows\\path', 'PATHEXT' => ".EXE") do
          android_env = Screengrab::AndroidEnvironment.new('screengrab\\spec\\fixtures\\complete_home_complete_path_windows\\android_home', nil)

          expect(android_env.android_home).to eq('screengrab\\spec\\fixtures\\complete_home_complete_path_windows\\android_home')
          expect(android_env.platform_tools_path).to eq('screengrab\\spec\\fixtures\\complete_home_complete_path_windows\\android_home\\platform-tools')
          expect(android_env.adb_path).to eq('screengrab\\spec\\fixtures\\complete_home_complete_path_windows\\android_home\\platform-tools\\adb.exe')
        end
      end
    end
  end
end
