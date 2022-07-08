describe Fastlane do
  describe Fastlane::FastFile do
    describe "install_on_device" do
      it "generates a valid command" do
        result = Fastlane::FastFile.new.parse("lane :test do
          install_on_device(ipa: 'demo.ipa')
        end").runner.execute(:test)
        expect(result).to eq("ios-deploy --bundle demo.ipa")
      end

      it "generates a valid command using app name with space" do
        ipa = "demo app.ipa"
        result = Fastlane::FastFile.new.parse("lane :test do
          install_on_device(ipa: '#{ipa}')
        end").runner.execute(:test)
        expect(result).to eq("ios-deploy --bundle #{ipa.shellescape}")
      end
    end
  end
end
