describe Fastlane do
  describe Fastlane::FastFile do
    describe "Create keychain Integration" do
      context "with name and password options" do
        it "works when keychain doesn't exist" do
          allow(Fastlane::Actions::CreateKeychainAction).to receive(:list_keychains).and_return(
            # first time
            [File.expand_path('~/Library/Keychains/login.keychain-db')],
            # after creation
            [File.expand_path('~/Library/Keychains/login.keychain-db'), File.expand_path('~/Library/Keychains/test.keychain')]
          )

          allow(Fastlane::Actions::CreateKeychainAction).to receive(:resolved_keychain_path).and_return(
            nil,
            File.expand_path('~/Library/Keychains/test.keychain')
          )

          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              name: 'test.keychain',
              password: 'testpassword',
            })
          end").runner.execute(:test)

          expect(result.size).to eq(3)
          expect(result[0]).to eq('security create-keychain -p testpassword ~/Library/Keychains/test.keychain')

          expect(result[1]).to start_with('security set-keychain-settings')
          expect(result[1]).to include('-t 300')
          expect(result[1]).to_not(include('-l'))
          expect(result[1]).to_not(include('-u'))
          expect(result[1]).to include('~/Library/Keychains/test.keychain')
          expect(result[2]).to start_with("security list-keychains -s")
          expect(result[2]).to end_with(File.expand_path('~/Library/Keychains/test.keychain').to_s)
        end

        it "work when keychain already exist" do
          allow(Fastlane::Actions::CreateKeychainAction).to receive(:list_keychains).and_return(
            [File.expand_path('~/Library/Keychains/login.keychain-db'), File.expand_path('~/Library/Keychains/test.keychain')]
          )

          allow(Fastlane::Actions::CreateKeychainAction).to receive(:resolved_keychain_path).and_return(
            File.expand_path('~/Library/Keychains/test.keychain')
          )

          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              name: 'test.keychain',
              password: 'testpassword',
            })
          end").runner.execute(:test)

          expect(result.size).to eq(1)
          expect(result[0]).to start_with('security set-keychain-settings')
          expect(result[0]).to include('-t 300')
          expect(result[0]).to_not(include('-l'))
          expect(result[0]).to_not(include('-u'))
          expect(result[0]).to include('~/Library/Keychains/test.keychain')
        end

        it "works with a password that contain spaces or `\"`" do
          password = "\"test password\""
          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              name: 'test.keychain',
              password: '#{password}',
            })
          end").runner.execute(:test)

          expect(result.size).to eq(3)
          expect(result[0]).to eq(%(security create-keychain -p #{password.shellescape} ~/Library/Keychains/test.keychain))
        end

        it "works with keychain-settings" do
          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              name: 'test.keychain',
              password: 'testpassword',
              timeout: 600,
              lock_when_sleeps: true,
              lock_after_timeout: true,
            })
          end").runner.execute(:test)

          expect(result.size).to eq(3)
          expect(result[0]).to eq('security create-keychain -p testpassword ~/Library/Keychains/test.keychain')

          expect(result[1]).to start_with('security set-keychain-settings')
          expect(result[1]).to include('-t 600')
          expect(result[1]).to include('-l')
          expect(result[1]).to include('-u')
          expect(result[1]).to include('~/Library/Keychains/test.keychain')
        end

        it "works with default_keychain" do
          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              name: 'test.keychain',
              password: 'testpassword',
              default_keychain: true,
            })
          end").runner.execute(:test)

          expect(result.size).to eq(4)
          expect(result[0]).to eq('security create-keychain -p testpassword ~/Library/Keychains/test.keychain')

          expect(result[1]).to eq('security default-keychain -s ~/Library/Keychains/test.keychain')

          expect(result[2]).to start_with('security set-keychain-settings')
          expect(result[2]).to include('-t 300')
          expect(result[2]).to_not(include('-l'))
          expect(result[2]).to_not(include('-u'))
          expect(result[2]).to include('~/Library/Keychains/test.keychain')
        end

        it "works with unlock" do
          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              name: 'test.keychain',
              password: 'testpassword',
              unlock: true,
            })
          end").runner.execute(:test)

          expect(result.size).to eq(4)
          expect(result[0]).to eq('security create-keychain -p testpassword ~/Library/Keychains/test.keychain')

          expect(result[1]).to eq('security unlock-keychain -p testpassword ~/Library/Keychains/test.keychain')

          expect(result[2]).to start_with('security set-keychain-settings')
          expect(result[2]).to include('-t 300')
          expect(result[2]).to_not(include('-l'))
          expect(result[2]).to_not(include('-u'))
          expect(result[2]).to include('~/Library/Keychains/test.keychain')
        end

        it "works with 'timeout: 0' to specify 'no timeout', skips -t param" do
          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              name: 'test.keychain',
              password: 'testpassword',
              unlock: true,
              timeout: 0
            })
          end").runner.execute(:test)

          expect(result.size).to eq(4)
          expect(result[0]).to eq('security create-keychain -p testpassword ~/Library/Keychains/test.keychain')

          expect(result[1]).to eq('security unlock-keychain -p testpassword ~/Library/Keychains/test.keychain')

          expect(result[2]).to start_with('security set-keychain-settings')
          expect(result[2]).to_not(include('-t'))
          expect(result[2]).to_not(include('-l'))
          expect(result[2]).to_not(include('-u'))
          expect(result[2]).to include('~/Library/Keychains/test.keychain')
        end

        it "works with all params" do
          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              name: 'test.keychain',
              password: 'testpassword',
              default_keychain: true,
              unlock: true,
              timeout: 600,
              lock_when_sleeps: true,
              lock_after_timeout: true,
              add_to_search_list: false,
            })
          end").runner.execute(:test)

          expect(result.size).to eq(4)
          expect(result[0]).to eq('security create-keychain -p testpassword ~/Library/Keychains/test.keychain')

          expect(result[1]).to eq('security default-keychain -s ~/Library/Keychains/test.keychain')
          expect(result[2]).to eq('security unlock-keychain -p testpassword ~/Library/Keychains/test.keychain')

          expect(result[3]).to start_with('security set-keychain-settings')
          expect(result[3]).to include('-t 600')
          expect(result[3]).to include('-l')
          expect(result[3]).to include('-u')
          expect(result[3]).to include('~/Library/Keychains/test.keychain')
        end

        it "sets the correct keychain path" do
          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              name: 'test.keychain',
              password: 'testpassword',
              default_keychain: true,
            })
          end").runner.execute(:test)

          expect(Fastlane::Actions.lane_context[Fastlane::Actions::SharedValues::KEYCHAIN_PATH]).to eq('~/Library/Keychains/test.keychain')
        end
      end

      context "with path and password options" do
        it "successfully creates the keychain" do
          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              path: '/tmp/test.keychain',
              password: 'testpassword',
              default_keychain: true,
              unlock: true,
              timeout: 600,
              lock_when_sleeps: true,
              lock_after_timeout: true,
              add_to_search_list: false,
            })
          end").runner.execute(:test)
          expect(result.size).to eq(4)
          expect(result[0]).to eq('security create-keychain -p testpassword /tmp/test.keychain')

          expect(result[1]).to eq('security default-keychain -s /tmp/test.keychain')
          expect(result[2]).to eq('security unlock-keychain -p testpassword /tmp/test.keychain')

          expect(result[3]).to start_with('security set-keychain-settings')
          expect(result[3]).to include('-t 600')
          expect(result[3]).to include('-l')
          expect(result[3]).to include('-u')
          expect(result[3]).to include('/tmp/test.keychain')
        end

        it "sets the correct keychain path" do
          result = Fastlane::FastFile.new.parse("lane :test do
            create_keychain ({
              path: '/tmp/test.keychain',
              password: 'testpassword',
              default_keychain: true,
            })
          end").runner.execute(:test)

          expect(Fastlane::Actions.lane_context[Fastlane::Actions::SharedValues::KEYCHAIN_PATH]).to eq('/tmp/test.keychain')
        end
      end
    end
  end
end
