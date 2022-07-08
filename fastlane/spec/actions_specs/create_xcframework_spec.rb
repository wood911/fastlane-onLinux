describe Fastlane do
  describe Fastlane::FastFile do
    describe "Create XCFramework Action" do
      before(:each) do
        allow(File).to receive(:exist?).and_call_original
        allow(File).to receive(:directory?).and_call_original
      end

      it "requires to either provide :frameworks or :libraries" do
        expect do
          Fastlane::FastFile.new.parse("lane :test do
            create_xcframework(
              output: 'UniversalFramework.xcframework'
            )
          end").runner.execute(:test)
        end.to raise_error("Please provide either :frameworks or :libraries to be packaged into the xcframework")
      end

      it "forbids to provide both :frameworks and :libraries" do
        allow(File).to receive(:exist?).with('FrameworkA.framework').and_return(true)
        allow(File).to receive(:directory?).with('FrameworkA.framework').and_return(true)
        allow(File).to receive(:exist?).with('LibraryA.so').and_return(true)

        expect do
          Fastlane::FastFile.new.parse("lane :test do
            create_xcframework(
              frameworks: ['FrameworkA.framework'],
              libraries: { 'LibraryA.so' => '' },
              output: 'UniversalFramework.xcframework'
            )
          end").runner.execute(:test)
        end.to raise_error("Unresolved conflict between options: 'frameworks' and 'libraries'")
      end

      context "when packaging frameworks" do
        context "which exist" do
          before(:each) do
            allow(File).to receive(:exist?).with('FrameworkA.framework').and_return(true)
            allow(File).to receive(:exist?).with('FrameworkB.framework').and_return(true)
          end

          context "and are directories" do
            before(:each) do
              allow(File).to receive(:directory?).with('FrameworkA.framework').and_return(true)
              allow(File).to receive(:directory?).with('FrameworkB.framework').and_return(true)
            end

            it "should work properly for public frameworks" do
              result = Fastlane::FastFile.new.parse("lane :test do
                create_xcframework(
                  frameworks: ['FrameworkA.framework', 'FrameworkB.framework'],
                  output: 'UniversalFramework.xcframework'
                )
              end").runner.execute(:test)

              expect(result).to eq('xcodebuild -create-xcframework ' \
                + '-framework "FrameworkA.framework" -framework "FrameworkB.framework" ' \
                + '-output "UniversalFramework.xcframework"')
            end

            it "should work properly for internal frameworks" do
              result = Fastlane::FastFile.new.parse("lane :test do
                create_xcframework(
                  frameworks: ['FrameworkA.framework', 'FrameworkB.framework'],
                  output: 'UniversalFramework.xcframework',
                  allow_internal_distribution: true
                )
              end").runner.execute(:test)

              expect(result).to eq('xcodebuild -create-xcframework ' \
                + '-framework "FrameworkA.framework" -framework "FrameworkB.framework" ' \
                + '-output "UniversalFramework.xcframework" ' \
                + '-allow-internal-distribution')
            end
          end

          context "and are not directories" do
            it "should fail due to wrong framework" do
              expect do
                Fastlane::FastFile.new.parse("lane :test do
                  create_xcframework(
                    frameworks: ['FrameworkA.framework', 'FrameworkB.framework'],
                    output: 'UniversalFramework.xcframework'
                  )
                end").runner.execute(:test)
              end.to raise_error("FrameworkA.framework doesn't seem to be a framework")
            end
          end
        end

        context "which don't exist" do
          it "should fail due to missing framework" do
            expect do
              Fastlane::FastFile.new.parse("lane :test do
                create_xcframework(
                  frameworks: ['FrameworkA.framework', 'FrameworkB.framework'],
                  output: 'UniversalFramework.xcframework'
                )
              end").runner.execute(:test)
            end.to raise_error("Couldn't find framework at FrameworkA.framework")
          end
        end
      end

      context "when rewriting existing xcframework" do
        before(:each) do
          allow(File).to receive(:exist?).with('FrameworkA.framework').and_return(true)
          allow(File).to receive(:exist?).with('FrameworkB.framework').and_return(true)
          allow(File).to receive(:directory?).with('FrameworkA.framework').and_return(true)
          allow(File).to receive(:directory?).with('FrameworkB.framework').and_return(true)
          allow(File).to receive(:directory?).with('UniversalFramework.xcframework').and_return(true)
        end

        it "should fail due to the deleted xcframework" do
          expect(FileUtils).to receive(:remove_dir).with('UniversalFramework.xcframework')

          Fastlane::FastFile.new.parse("lane :test do
            create_xcframework(
              frameworks: ['FrameworkA.framework', 'FrameworkB.framework'],
              output: 'UniversalFramework.xcframework'
            )
          end").runner.execute(:test)
        end
      end

      context "when packaging libraries" do
        context "which exist" do
          before(:each) do
            allow(File).to receive(:exist?).with('LibraryA.so').and_return(true)
            allow(File).to receive(:exist?).with('LibraryB.so').and_return(true)
          end

          context "which headers is a directory" do
            before(:each) do
              allow(File).to receive(:directory?).with('headers').and_return(true)
            end

            it "should work properly for public frameworks" do
              result = Fastlane::FastFile.new.parse("lane :test do
                create_xcframework(
                  libraries: { 'LibraryA.so' => '', 'LibraryB.so' => 'headers' },
                  output: 'UniversalFramework.xcframework'
                )
              end").runner.execute(:test)

              expect(result).to eq('xcodebuild -create-xcframework ' \
                + '-library "LibraryA.so" -library "LibraryB.so" -headers "headers" ' \
                + '-output "UniversalFramework.xcframework"')
            end

            it "should work properly for internal frameworks" do
              result = Fastlane::FastFile.new.parse("lane :test do
                create_xcframework(
                  libraries: { 'LibraryA.so' => '', 'LibraryB.so' => 'headers' },
                  output: 'UniversalFramework.xcframework',
                  allow_internal_distribution: true
                )
              end").runner.execute(:test)

              expect(result).to eq('xcodebuild -create-xcframework ' \
                + '-library "LibraryA.so" -library "LibraryB.so" -headers "headers" ' \
                + '-output "UniversalFramework.xcframework" ' \
                + '-allow-internal-distribution')
            end
          end

          context "which headers is not a directory" do
            it "should fail due to wrong headers directory" do
              expect do
                Fastlane::FastFile.new.parse("lane :test do
                  create_xcframework(
                    libraries: { 'LibraryA.so' => '', 'LibraryB.so' => 'headers' },
                    output: 'UniversalFramework.xcframework'
                  )
                end").runner.execute(:test)
              end.to raise_error("headers doesn't exist or is not a directory")
            end
          end
        end

        context "which don't exist" do
          it "should fail due to missing library" do
            expect do
              Fastlane::FastFile.new.parse("lane :test do
                create_xcframework(
                  libraries: { 'LibraryA.so' => '' },
                  output: 'UniversalFramework.xcframework'
                )
              end").runner.execute(:test)
            end.to raise_error("Couldn't find library at LibraryA.so")
          end
        end
      end
    end
  end
end
