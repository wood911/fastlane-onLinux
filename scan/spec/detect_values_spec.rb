describe Scan do
  describe Scan::DetectValues do
    describe 'Xcode config handling' do
      before do
        options = { project: "./scan/examples/standard/app.xcodeproj" }
        FileUtils.mkdir_p("./scan/examples/standard/app.xcodeproj/project.xcworkspace/xcuserdata/#{ENV['USER']}.xcuserdatad/")
        FileUtils.copy("./scan/examples/standard/WorkspaceSettings.xcsettings", "./scan/examples/standard/app.xcodeproj/project.xcworkspace/xcuserdata/#{ENV['USER']}.xcuserdatad/WorkspaceSettings.xcsettings")
        Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
        @project = FastlaneCore::Project.new(Scan.config)
      end

      it "fetches the path from the Xcode config", requires_xcodebuild: true do
        derived_data = Scan.config[:derived_data_path]
        expect(derived_data).to match(File.expand_path("./scan/examples/standard/"))
      end
    end

    describe "#detect_destination" do
      it "ios", requires_xcodebuild: true do
        options = { project: "./scan/examples/standard/app.xcodeproj" }
        Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
        expect(Scan.config[:destination].first).to match(/platform=iOS/)
      end

      context "catalyst" do
        it "ios", requires_xcodebuild: true do
          options = { project: "./scan/examples/standard/app.xcodeproj" }
          expect_any_instance_of(FastlaneCore::Project).to receive(:supports_mac_catalyst?).and_return(true)
          Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
          expect(Scan.config[:destination].first).to match(/platform=iOS/)
        end

        it "mac", requires_xcodebuild: true do
          options = { project: "./scan/examples/standard/app.xcodeproj", catalyst_platform: "macos" }
          expect_any_instance_of(FastlaneCore::Project).to receive(:supports_mac_catalyst?).and_return(true)
          Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
          expect(Scan.config[:destination].first).to match(/platform=macOS,variant=Mac Catalyst/)
        end
      end
    end

    describe "validation" do
      it "advises of problems with multiple output_types and a custom_report_file_name", requires_xcodebuild: true do
        options = {
          project: "./scan/examples/standard/app.xcodeproj",
          # use default output types
          custom_report_file_name: 'report.xml'
        }
        expect(FastlaneCore::UI).to receive(:user_error!).with("Using a :custom_report_file_name with multiple :output_types (html,junit) will lead to unexpected results. Use :output_files instead.")
        Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
      end

      it "does not advise of a problem with one output_type and a custom_report_file_name", requires_xcodebuild: true do
        options = {
          project: "./scan/examples/standard/app.xcodeproj",
          output_types: 'junit',
          custom_report_file_name: 'report.xml'
        }
        expect(FastlaneCore::UI).not_to(receive(:user_error!))
        Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
      end
    end

    describe "value coercion" do
      it "coerces only_testing to be an array", requires_xcodebuild: true do
        options = {
          project: "./scan/examples/standard/app.xcodeproj",
          only_testing: "Bundle/SuiteA"
        }
        Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
        expect(Scan.config[:only_testing]).to eq(["Bundle/SuiteA"])
      end

      it "coerces skip_testing to be an array", requires_xcodebuild: true do
        options = {
          project: "./scan/examples/standard/app.xcodeproj",
          skip_testing: "Bundle/SuiteA,Bundle/SuiteB"
        }
        Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
        expect(Scan.config[:skip_testing]).to eq(["Bundle/SuiteA", "Bundle/SuiteB"])
      end

      it "leaves skip_testing as an array", requires_xcodebuild: true do
        options = {
          project: "./scan/examples/standard/app.xcodeproj",
          skip_testing: ["Bundle/SuiteA", "Bundle/SuiteB"]
        }
        Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
        expect(Scan.config[:skip_testing]).to eq(["Bundle/SuiteA", "Bundle/SuiteB"])
      end

      it "coerces only_test_configurations to be an array", requires_xcodebuild: true do
        options = {
          project: "./scan/examples/standard/app.xcodeproj",
          only_test_configurations: "ConfigurationA"
        }
        Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
        expect(Scan.config[:only_test_configurations]).to eq(["ConfigurationA"])
      end

      it "coerces skip_test_configurations to be an array", requires_xcodebuild: true do
        options = {
          project: "./scan/examples/standard/app.xcodeproj",
          skip_test_configurations: "ConfigurationA,ConfigurationB"
        }
        Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
        expect(Scan.config[:skip_test_configurations]).to eq(["ConfigurationA", "ConfigurationB"])
      end

      it "leaves skip_test_configurations as an array", requires_xcodebuild: true do
        options = {
          project: "./scan/examples/standard/app.xcodeproj",
          skip_test_configurations: ["ConfigurationA", "ConfigurationB"]
        }
        Scan.config = FastlaneCore::Configuration.create(Scan::Options.available_options, options)
        expect(Scan.config[:skip_test_configurations]).to eq(["ConfigurationA", "ConfigurationB"])
      end
    end
  end
end
