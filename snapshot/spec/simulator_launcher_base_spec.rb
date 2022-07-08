describe Snapshot do
  describe Snapshot::SimulatorLauncherBase do
    let(:device_udid) { "123456789" }
    let(:paths) { ['./logo.png'] }

    describe '#add_media' do
      it "should call simctl addmedia" do
        allow(Snapshot::TestCommandGenerator).to receive(:device_udid).and_return(device_udid)

        expect(Fastlane::Helper).to receive(:backticks)
          .with("xcrun instruments -w #{device_udid} &> /dev/null")
          .and_return("").exactly(1).times

        expect(Fastlane::Helper).to receive(:backticks)
          .with("xcrun simctl addmedia #{device_udid} #{paths.join(' ')} &> /dev/null")
          .and_return("").exactly(1).times

        # Verify that backticks isn't called for the fallback to addphoto/addvideo
        expect(Fastlane::Helper).to receive(:backticks).with(anything).and_return(anything).exactly(0).times

        launcher = Snapshot::SimulatorLauncherBase.new
        launcher.add_media(['phone'], 'photo', paths)
      end

      it "should call simctl addmedia and fallback to addphoto" do
        allow(Snapshot::TestCommandGenerator).to receive(:device_udid).and_return(device_udid)

        expect(Fastlane::Helper).to receive(:backticks)
          .with("xcrun instruments -w #{device_udid} &> /dev/null")
          .and_return("").exactly(1).times

        expect(Fastlane::Helper).to receive(:backticks)
          .with("xcrun simctl addmedia #{device_udid} #{paths.join(' ')} &> /dev/null")
          .and_return("usage: simctl [--noxpc] [--set <path>] [--profiles <path>] <subcommand> ...\n").exactly(1).times

        expect(Fastlane::Helper).to receive(:backticks).with(anything).and_return(anything).exactly(1).times

        launcher = Snapshot::SimulatorLauncherBase.new
        launcher.add_media(['phone'], 'photo', paths)
      end
    end
  end
end
