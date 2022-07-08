describe Fastlane do
  describe Fastlane::FastFile do
    describe "Add Git Tag Integration" do
      require 'shellwords'

      build_number = 1337

      before :each do
        Fastlane::Actions.lane_context[Fastlane::Actions::SharedValues::BUILD_NUMBER] = build_number
      end

      context "when 'includes_lane' option is enabled" do
        it "appends lane_name in the tag and git message" do
          lane_name = "fake_lane_name"
          message = "builds/#{lane_name}/#{build_number} (fastlane)"
          tag = "builds/#{lane_name}/#{build_number}"

          expect(UI).to receive(:message).with("Adding git tag '#{tag.shellescape}' 🎯.")
          expect(Fastlane::Actions).to receive(:sh).with("git tag -am #{message.shellescape} #{tag.shellescape}")

          Fastlane::Actions.lane_context[Fastlane::Actions::SharedValues::LANE_NAME] = lane_name
          options = FastlaneCore::Configuration.create(Fastlane::Actions::AddGitTagAction.available_options, {})

          Fastlane::Actions::AddGitTagAction.run(options)
        end

        it "removes spaces from lane_name before appending it in the tag and git message" do
          lane_name = "fake lane name with spaces"
          lane_name_without_spaces = "fakelanenamewithspaces"
          message = "builds/#{lane_name_without_spaces}/#{build_number} (fastlane)"
          tag = "builds/#{lane_name_without_spaces}/#{build_number}"

          expect(UI).to receive(:message).with("Adding git tag '#{tag.shellescape}' 🎯.")
          expect(Fastlane::Actions).to receive(:sh).with("git tag -am #{message.shellescape} #{tag.shellescape}")

          Fastlane::Actions.lane_context[Fastlane::Actions::SharedValues::LANE_NAME] = lane_name
          options = FastlaneCore::Configuration.create(Fastlane::Actions::AddGitTagAction.available_options, {})

          Fastlane::Actions::AddGitTagAction.run(options)
        end
      end

      context "when 'includes_lane' option is not enabled" do
        it "doesn't append lane_name in the tag and git message" do
          lane_name = "fake_lane_name"
          message = "builds/#{build_number} (fastlane)"
          tag = "builds/#{build_number}"

          expect(UI).to receive(:message).with("Adding git tag '#{tag.shellescape}' 🎯.")
          expect(Fastlane::Actions).to receive(:sh).with("git tag -am #{message.shellescape} #{tag.shellescape}")

          Fastlane::Actions.lane_context[Fastlane::Actions::SharedValues::LANE_NAME] = lane_name
          options = FastlaneCore::Configuration.create(Fastlane::Actions::AddGitTagAction.available_options, {
            includes_lane: false,
          })

          Fastlane::Actions::AddGitTagAction.run(options)
        end
      end

      it "generates a tag based on existing context" do
        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag
        end").runner.execute(:test)

        message = "builds/test/1337 (fastlane)"
        tag = "builds/test/1337"
        expect(result).to eq("git tag -am #{message.shellescape} #{tag.shellescape}")
      end

      it "allows you to specify grouping and build number" do
        specified_build_number = 42
        grouping = 'grouping'

        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            grouping: '#{grouping}',
            build_number: #{specified_build_number},
          })
        end").runner.execute(:test)

        message = "#{grouping}/test/#{specified_build_number} (fastlane)"
        tag = "#{grouping}/test/#{specified_build_number}"
        expect(result).to eq("git tag -am #{message.shellescape} #{tag.shellescape}")
      end

      it "allows you to not include the current lane in the tag and message" do
        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            includes_lane: false,
          })
        end").runner.execute(:test)

        message = "builds/#{build_number} (fastlane)"
        tag = "builds/#{build_number}"
        expect(result).to eq("git tag -am #{message.shellescape} #{tag.shellescape}")
      end

      it "allows you to specify a prefix" do
        prefix = '16309-'

        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            prefix: '#{prefix}',
          })
        end").runner.execute(:test)

        message = "builds/test/#{prefix}#{build_number} (fastlane)"
        tag = "builds/test/#{prefix}#{build_number}"
        expect(result).to eq("git tag -am #{message.shellescape} #{tag.shellescape}")
      end

      it "allows you to specify a postfix" do
        postfix = '-RC1'

        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            postfix: '#{postfix}',
          })
        end").runner.execute(:test)

        message = "builds/test/#{build_number}#{postfix} (fastlane)"
        tag = "builds/test/#{build_number}#{postfix}"
        expect(result).to eq("git tag -am #{message.shellescape} #{tag.shellescape}")
      end

      it "allows you to specify your own tag" do
        tag = '2.0.0'

        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            tag: '#{tag}',
          })
        end").runner.execute(:test)

        message = "#{tag} (fastlane)"
        expect(result).to eq("git tag -am #{message.shellescape} #{tag.shellescape}")
      end

      it "raises error if no tag or build_number are provided" do
        Fastlane::Actions.lane_context[Fastlane::Actions::SharedValues::BUILD_NUMBER] = nil

        expect do
          Fastlane::FastFile.new.parse("lane :test do
            add_git_tag ({})
          end").runner.execute(:test)
        end.to raise_error(/No value found for 'tag' or 'build_number'. At least one of them must be provided. Note that if you do specify a tag, all other arguments are ignored./)
      end

      it "specified tag overrides generate tag" do
        tag = '2.0.0'

        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            tag: '#{tag}',
            grouping: 'grouping',
            build_number: 'build_number',
            prefix: 'prefix',
          })
        end").runner.execute(:test)

        message = "#{tag} (fastlane)"
        expect(result).to eq("git tag -am #{message.shellescape} #{tag.shellescape}")
      end

      it "allows you to specify your own message" do
        tag = '2.0.0'
        message = "message"

        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            tag: '#{tag}',
            message: '#{message}'
          })
        end").runner.execute(:test)

        expect(result).to eq("git tag -am #{message.shellescape} #{tag.shellescape}")
      end

      it "properly shell escapes its message" do
        tag = '2.0.0'
        message = "message with 'quotes' (and parens)"

        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            tag: '#{tag}',
            message: \"#{message}\"
          })
        end").runner.execute(:test)

        expect(result).to eq("git tag -am #{message.shellescape} #{tag.shellescape}")
      end

      it "allows you to force the tag creation" do
        tag = '2.0.0'
        message = "message"

        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            tag: '#{tag}',
            message: '#{message}',
            force: true
          })
        end").runner.execute(:test)

        expect(result).to eq("git tag -am #{message.shellescape} --force #{tag.shellescape}")
      end

      it "allows you to specify the commit where to add the tag" do
        tag = '2.0.0'
        commit = 'beta_tag'
        message = "message"

        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            tag: '#{tag}',
            message: '#{message}',
            commit: '#{commit}'
          })
        end").runner.execute(:test)

        expect(result).to eq("git tag -am #{message.shellescape} #{tag.shellescape} #{commit}")
      end

      it "allows you to sign the tag using the default e-mail address's key." do
        tag = '2.0.0'
        message = "message"

        result = Fastlane::FastFile.new.parse("lane :test do
          add_git_tag ({
            tag: '#{tag}',
            message: '#{message}',
            sign: true
          })
        end").runner.execute(:test)

        expect(result).to eq("git tag -am #{message.shellescape} -s #{tag.shellescape}")
      end
    end
  end
end
