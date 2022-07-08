describe Fastlane do
  describe Fastlane::FastFile do
    describe "Carthage Integration" do
      it "raises an error if command is invalid" do
        expect do
          Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'thisistest'
            )
          end").runner.execute(:test)
        end.to raise_error("Please pass a valid command. Use one of the following: build, bootstrap, update, archive")
      end

      it "raises an error if platform is invalid" do
        expect do
          Fastlane::FastFile.new.parse("lane :test do
            carthage(
              platform: 'thisistest'
            )
          end").runner.execute(:test)
        end.to raise_error("Please pass a valid platform. Use one of the following: all, iOS, Mac, tvOS, watchOS")
      end

      it "default use case is boostrap" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "sets the command to build" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(command: 'build')
          end").runner.execute(:test)

        expect(result).to eq("carthage build")
      end

      it "sets the command to bootstrap" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(command: 'bootstrap')
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "sets the command to update" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(command: 'update')
          end").runner.execute(:test)

        expect(result).to eq("carthage update")
      end

      it "sets the command to archive" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(command: 'archive')
          end").runner.execute(:test)

        expect(result).to eq("carthage archive")
      end

      it "adds use-ssh flag to command if use_ssh is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_ssh: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --use-ssh")
      end

      it "doesn't add a use-ssh flag to command if use_ssh is set to false" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_ssh: false
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "adds use-submodules flag to command if use_submodules is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_submodules: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --use-submodules")
      end

      it "doesn't add a use-submodules flag to command if use_submodules is set to false" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_submodules: false
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "adds use-netrc flag to command if use_netrc is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_netrc: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --use-netrc")
      end

      it "doesn't add a use-netrc flag to command if use_netrc is set to false" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_netrc: false
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "adds no-use-binaries flag to command if use_binaries is set to false" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_binaries: false
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --no-use-binaries")
      end

      it "doesn't add a no-use-binaries flag to command if use_binaries is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_binaries: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "adds no-checkout flag to command if no_checkout is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              no_checkout: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --no-checkout")
      end

      it "adds no-build flag to command if no_build is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              no_build: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --no-build")
      end

      it "does not add a no-build flag to command if no_build is set to false" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              no_build: false
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "adds no-skip-current flag to command if no_skip_current is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'build',
              no_skip_current: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage build --no-skip-current")
      end

      it "doesn't add a no-skip-current flag to command if no_skip_current is set to false" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'build',
              no_skip_current: false
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage build")
      end

      it "adds verbose flag to command if verbose is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              verbose: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --verbose")
      end

      it "does not add a verbose flag to command if verbose is set to false" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              verbose: false
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "sets the platform to all" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              platform: 'all'
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --platform all")
      end

      it "sets the platform to iOS" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              platform: 'iOS'
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --platform iOS")
      end

      it "sets the platform to (downcase) ios" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              platform: 'ios'
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --platform ios")
      end

      it "sets the platform to Mac" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              platform: 'Mac'
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --platform Mac")
      end

      it "sets the platform to tvOS" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              platform: 'tvOS'
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --platform tvOS")
      end

      it "sets the platform to watchOS" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              platform: 'watchOS'
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --platform watchOS")
      end

      it "can be set to multiple the platforms" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              platform: 'iOS,Mac'
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --platform iOS,Mac")
      end

      it "sets the configuration to Release" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              configuration: 'Release'
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --configuration Release")
      end

      it "raises an error if configuration is empty" do
        expect do
          Fastlane::FastFile.new.parse("lane :test do
            carthage(
              configuration: ' '
            )
          end").runner.execute(:test)
        end.to raise_error("Please pass a valid build configuration. You can review the list of configurations for this project using the command: xcodebuild -list")
      end

      it "sets the toolchain to Swift_2_3" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              toolchain: 'com.apple.dt.toolchain.Swift_2_3'
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --toolchain com.apple.dt.toolchain.Swift_2_3")
      end

      it "sets the project directory to other" do
        result = Fastlane::FastFile.new.parse("lane :test do
          carthage(project_directory: 'other')
        end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --project-directory other")
      end

      it "sets the project directory to other and the toolchain to Swift_2_3" do
        result = Fastlane::FastFile.new.parse("lane :test do
          carthage(toolchain: 'com.apple.dt.toolchain.Swift_2_3', project_directory: 'other')
        end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --toolchain com.apple.dt.toolchain.Swift_2_3 --project-directory other")
      end

      it "does not add a cache_builds flag to command if cache_builds is set to false" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              cache_builds: false
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "add a cache_builds flag to command if cache_builds is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              cache_builds: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --cache-builds")
      end

      it "does not add a use_xcframeworks flag to command if use_xcframeworks is set to false" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_xcframeworks: false
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "add a use_xcframeworks flag to command if use_xcframeworks is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_xcframeworks: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap --use-xcframeworks")
      end

      it "does not add a archive flag to command if archive is set to false" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'build',
              archive: false
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage build")
      end

      it "add a archive flag to command if archive is set to true" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'build',
              archive: true
            )
          end").runner.execute(:test)

        expect(result).to eq("carthage build --archive")
      end

      it "does not set the project directory if none is provided" do
        result = Fastlane::FastFile.new.parse("lane :test do
          carthage
        end").runner.execute(:test)

        expect(result).to eq("carthage bootstrap")
      end

      it "use custom derived data" do
        path = "../derived data"
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              derived_data: '#{path}'
            )
          end").runner.execute(:test)

        expect(result).to \
          eq("carthage bootstrap --derived-data #{path.shellescape}")
      end

      it "use custom executable" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              executable: 'custom_carthage'
            )
          end").runner.execute(:test)

        expect(result).to \
          eq("custom_carthage bootstrap")
      end

      it "updates with a single dependency" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'update',
              dependencies: ['TestDependency']
            )
          end").runner.execute(:test)

        expect(result).to \
          eq("carthage update TestDependency")
      end

      it "updates with multiple dependencies" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'update',
              dependencies: ['TestDependency1', 'TestDependency2']
            )
          end").runner.execute(:test)

        expect(result).to \
          eq("carthage update TestDependency1 TestDependency2")
      end

      it "builds with a single dependency" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'build',
              dependencies: ['TestDependency']
            )
          end").runner.execute(:test)

        expect(result).to \
          eq("carthage build TestDependency")
      end

      it "builds with multiple dependencies" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'build',
              dependencies: ['TestDependency1', 'TestDependency2']
            )
          end").runner.execute(:test)

        expect(result).to \
          eq("carthage build TestDependency1 TestDependency2")
      end

      it "bootstraps with a single dependency" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'bootstrap',
              dependencies: ['TestDependency']
            )
          end").runner.execute(:test)

        expect(result).to \
          eq("carthage bootstrap TestDependency")
      end

      it "bootstraps with multiple dependencies" do
        result = Fastlane::FastFile.new.parse("lane :test do
            carthage(
              command: 'bootstrap',
              dependencies: ['TestDependency1', 'TestDependency2']
            )
          end").runner.execute(:test)

        expect(result).to \
          eq("carthage bootstrap TestDependency1 TestDependency2")
      end

      it "works with no parameters" do
        expect do
          Fastlane::FastFile.new.parse("lane :test do
            carthage
          end").runner.execute(:test)
        end.not_to(raise_error)
      end

      it "works with valid parameters" do
        expect do
          Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_ssh: true,
              use_submodules: true,
              use_binaries: false,
              platform: 'iOS'
            )
          end").runner.execute(:test)
        end.not_to(raise_error)
      end

      it "works with cache_builds" do
        expect do
          Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_ssh: true,
              use_submodules: true,
              use_binaries: false,
              cache_builds: true,
              platform: 'iOS'
            )
          end").runner.execute(:test)
        end.not_to(raise_error)
      end

      it "works with new resolver" do
        expect do
          Fastlane::FastFile.new.parse("lane :test do
            carthage(
              use_ssh: true,
              use_submodules: true,
              use_binaries: false,
              cache_builds: true,
              platform: 'iOS',
              new_resolver: true
            )
          end").runner.execute(:test)
        end.not_to(raise_error)
      end

      context "when specify framework" do
        let(:command) { 'archive' }

        context "when command is archive" do
          it "adds one framework" do
            result = Fastlane::FastFile.new.parse("lane :test do
                carthage(command: '#{command}', frameworks: ['myframework'])
              end").runner.execute(:test)
            expect(result).to eq("carthage archive myframework")
          end

          it "adds multiple frameworks" do
            result = Fastlane::FastFile.new.parse("lane :test do
                carthage(command: '#{command}', frameworks: ['myframework', 'myframework2'])
              end").runner.execute(:test)
            expect(result).to eq("carthage archive myframework myframework2")
          end
        end

        context "when command is update" do
          let(:command) { 'update' }

          it "raises an exception" do
            expect do
              Fastlane::FastFile.new.parse("lane :test do
                  carthage(command: '#{command}', frameworks: ['myframework', 'myframework2'])
                end").runner.execute(:test)
            end.to raise_error("Frameworks option is available only for 'archive' command.")
          end
        end

        context "when command is build" do
          let(:command) { 'build' }

          it "raises an exception" do
            expect do
              Fastlane::FastFile.new.parse("lane :test do
                  carthage(command: '#{command}', frameworks: ['myframework', 'myframework2'])
                end").runner.execute(:test)
            end.to raise_error("Frameworks option is available only for 'archive' command.")
          end
        end

        context "when command is bootstrap" do
          let(:command) { 'bootstrap' }

          it "raises an exception" do
            expect do
              Fastlane::FastFile.new.parse("lane :test do
                  carthage(command: '#{command}', frameworks: ['myframework', 'myframework2'])
                end").runner.execute(:test)
            end.to raise_error("Frameworks option is available only for 'archive' command.")
          end
        end
      end

      context "when specify output" do
        let(:command) { 'archive' }

        context "when command is archive" do
          it "adds the output option" do
            result = Fastlane::FastFile.new.parse("lane :test do
                carthage(command: '#{command}', output: 'bla.framework.zip')
              end").runner.execute(:test)
            expect(result).to eq("carthage archive --output bla.framework.zip")
          end
        end

        context "when command is update" do
          let(:command) { 'update' }

          it "raises an exception" do
            expect do
              Fastlane::FastFile.new.parse("lane :test do
                  carthage(command: '#{command}', output: 'bla.framework.zip')
                end").runner.execute(:test)
            end.to raise_error("Output option is available only for 'archive' command.")
          end
        end

        context "when command is build" do
          let(:command) { 'build' }

          it "raises an exception" do
            expect do
              Fastlane::FastFile.new.parse("lane :test do
                  carthage(command: '#{command}', output: 'bla.framework.zip')
                end").runner.execute(:test)
            end.to raise_error("Output option is available only for 'archive' command.")
          end
        end

        context "when command is bootstrap" do
          let(:command) { 'bootstrap' }

          it "raises an exception" do
            expect do
              Fastlane::FastFile.new.parse("lane :test do
                  carthage(command: '#{command}', output: 'bla.framework.zip')
                end").runner.execute(:test)
            end.to raise_error("Output option is available only for 'archive' command.")
          end
        end
      end

      context "when specify log_path" do
        context "when command is archive" do
          let(:command) { 'archive' }
          it "--log-path option is not present" do
            expect do
              Fastlane::FastFile.new.parse("lane :test do
                carthage(command: '#{command}', log_path: 'bla.log')
              end").runner.execute(:test)
            end.to raise_error("Log path option is available only for 'build', 'bootstrap', and 'update' command.")
          end
        end

        context "when command is update" do
          let(:command) { 'update' }

          it "--log-path option is present" do
            result = Fastlane::FastFile.new.parse("lane :test do
                carthage(command: '#{command}', log_path: 'bla.log')
              end").runner.execute(:test)
            expect(result).to eq("carthage update --log-path bla.log")
          end
        end

        context "when command is build" do
          let(:command) { 'build' }

          it "--log-path option is present" do
            result = Fastlane::FastFile.new.parse("lane :test do
                carthage(command: '#{command}', log_path: 'bla.log')
              end").runner.execute(:test)
            expect(result).to eq("carthage build --log-path bla.log")
          end
        end

        context "when command is bootstrap" do
          let(:command) { 'bootstrap' }

          it "--log-path option is present" do
            result = Fastlane::FastFile.new.parse("lane :test do
                carthage(command: '#{command}', log_path: 'bla.log')
              end").runner.execute(:test)
            expect(result).to eq("carthage bootstrap --log-path bla.log")
          end
        end

        context "when specify derived_data" do
          context "when command is archive" do
            let(:command) { 'archive' }
            it "--derived-data option should not be present, even if ENV is set" do
              # Stub the environment variable specifying the derived data path
              stub_const('ENV', { 'FL_CARTHAGE_DERIVED_DATA' => './derived_data' })
              result = Fastlane::FastFile.new.parse("lane :test do
                carthage(command: '#{command}')
              end").runner.execute(:test)
              expect(result).to eq("carthage archive")
            end
          end
        end

        context "when --use-xcframeworks option is present with valid command" do
          it "adds the use_xcframeworks option" do
            ['update', 'build', 'bootstrap'].each do |command|
              result = Fastlane::FastFile.new.parse("lane :test do
                carthage(command: '#{command}', use_xcframeworks: true)
              end").runner.execute(:test)
              expect(result).to eq("carthage #{command} --use-xcframeworks")
            end
          end
        end
      end

      context "when specify archive" do
        context "when command is build" do
          let(:command) { 'build' }

          it "adds the archive option" do
            result = Fastlane::FastFile.new.parse("lane :test do
                carthage(command: '#{command}', archive: true)
              end").runner.execute(:test)
            expect(result).to eq("carthage build --archive")
          end
        end

        context "when archive option is present with invalid command" do
          it "raises an exception" do
            ['archive', 'update', 'bootstrap'].each do |command|
              expect do
                Fastlane::FastFile.new.parse("lane :test do
                    carthage(command: '#{command}', archive: true)
                  end").runner.execute(:test)
              end.to raise_error("Archive option is available only for 'build' command.")
            end
          end
        end
      end
    end
  end
end
