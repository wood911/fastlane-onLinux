describe Fastlane do
  describe Fastlane::FastFile do
    describe "danger integration" do
      before :each do
        allow(FastlaneCore::FastlaneFolder).to receive(:path).and_return(nil)
      end

      it "default use case" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger")
      end

      it "no bundle exec" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(use_bundle_exec: false)
        end").runner.execute(:test)

        expect(result).to eq("danger")
      end

      it "appends verbose" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(verbose: true)
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger --verbose")
      end

      it "sets github token" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(github_api_token: '1234')
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger")
        expect(ENV['DANGER_GITHUB_API_TOKEN']).to eq("1234")
      end

      it "appends danger_id" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(danger_id: 'unit-tests')
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger --danger_id=unit-tests")
      end

      it "appends dangerfile" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(dangerfile: 'test/OtherDangerfile')
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger --dangerfile=test/OtherDangerfile")
      end

      it "appends fail-on-errors flag when set" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(fail_on_errors: true)
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger --fail-on-errors=true")
      end

      it "does not append fail-on-errors flag when unset" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(fail_on_errors: false)
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger")
      end

      it "appends new-comment flag when set" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(new_comment: true)
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger --new-comment")
      end

      it "does not append new-comment flag when unset" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(new_comment: false)
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger")
      end

      it "appends remove-previous-comments flag when set" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(remove_previous_comments: true)
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger --remove-previous-comments")
      end

      it "does not append remove-previous-comments flag when unset" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(remove_previous_comments: false)
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger")
      end

      it "appends base" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(base: 'master')
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger --base=master")
      end

      it "appends head" do
        result = Fastlane::FastFile.new.parse("lane :test do
          danger(head: 'master')
        end").runner.execute(:test)

        expect(result).to eq("bundle exec danger --head=master")
      end
    end
  end
end
