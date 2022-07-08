require 'deliver/submit_for_review'
require 'ostruct'

describe Deliver::SubmitForReview do
  let(:review_submitter) { Deliver::SubmitForReview.new }

  describe 'submit app' do
    let(:app) { double('app') }
    let(:edit_version) do
      double('edit_version',
             version_string: "1.0.0")
    end
    let(:selected_build) { double('selected_build') }
    let(:idfa_declaration) { double('idfa_declaration') }

    before do
      allow(Deliver).to receive(:cache).and_return({ app: app })
    end

    context 'submit fails' do
      it 'no version' do
        options = {
          platform: Spaceship::ConnectAPI::Platform::IOS
        }

        expect(app).to receive(:get_edit_app_store_version).and_return(nil)

        expect(UI).to receive(:user_error!).with(/Cannot submit for review - could not find an editable version for/).and_raise("boom")

        expect do
          review_submitter.submit!(options)
        end.to raise_error("boom")
      end

      it 'needs to set export_compliance_uses_encryption' do
        options = {
          platform: Spaceship::ConnectAPI::Platform::IOS
        }

        expect(app).to receive(:get_edit_app_store_version).and_return(edit_version)
        expect(review_submitter).to receive(:select_build).and_return(selected_build)

        expect(selected_build).to receive(:uses_non_exempt_encryption).and_return(nil)

        expect(UI).to receive(:user_error!).with(/Export compliance is required to submit/).and_raise("boom")

        expect do
          review_submitter.submit!(options)
        end.to raise_error("boom")
      end

      it 'needs to set export_compliance_uses_encryption' do
        options = {
          platform: Spaceship::ConnectAPI::Platform::IOS
        }

        expect(app).to receive(:get_edit_app_store_version).and_return(edit_version)
        expect(review_submitter).to receive(:select_build).and_return(selected_build)

        expect(selected_build).to receive(:uses_non_exempt_encryption).and_return(false)

        expect(edit_version).to receive(:fetch_idfa_declaration).and_return(nil)
        expect(edit_version).to receive(:uses_idfa).and_return(nil)

        expect(UI).to receive(:user_error!).with(/Use of Advertising Identifier \(IDFA\) is required to submit/).and_raise("boom")

        expect do
          review_submitter.submit!(options)
        end.to raise_error("boom")
      end
    end

    context 'submits successfully' do
      it 'no options' do
        options = {
          platform: Spaceship::ConnectAPI::Platform::IOS
        }

        expect(app).to receive(:get_edit_app_store_version).and_return(edit_version)
        expect(review_submitter).to receive(:select_build).and_return(selected_build)

        expect(selected_build).to receive(:uses_non_exempt_encryption).and_return(false)

        expect(edit_version).to receive(:fetch_idfa_declaration).and_return(nil)
        expect(edit_version).to receive(:uses_idfa).and_return(false)

        expect(edit_version).to receive(:create_app_store_version_submission)

        review_submitter.submit!(options)
      end

      context 'export_compliance_uses_encryption' do
        it 'sets to false' do
          options = {
            platform: Spaceship::ConnectAPI::Platform::IOS,
            submission_information: {
              export_compliance_uses_encryption: false
            }
          }

          expect(app).to receive(:get_edit_app_store_version).and_return(edit_version)
          expect(review_submitter).to receive(:select_build).and_return(selected_build)

          expect(selected_build).to receive(:uses_non_exempt_encryption).and_return(nil)
          expect(selected_build).to receive(:update).with(attributes: { usesNonExemptEncryption: false }).and_return(selected_build)
          expect(selected_build).to receive(:uses_non_exempt_encryption).and_return(false)

          expect(edit_version).to receive(:fetch_idfa_declaration).and_return(nil)
          expect(edit_version).to receive(:uses_idfa).and_return(false)

          expect(edit_version).to receive(:create_app_store_version_submission)

          review_submitter.submit!(options)
        end
      end

      context 'content_rights_contains_third_party_content' do
        it 'sets to true' do
          options = {
            platform: Spaceship::ConnectAPI::Platform::IOS,
            submission_information: {
              content_rights_contains_third_party_content: true
            }
          }

          expect(app).to receive(:get_edit_app_store_version).and_return(edit_version)
          expect(review_submitter).to receive(:select_build).and_return(selected_build)

          expect(selected_build).to receive(:uses_non_exempt_encryption).and_return(false)

          expect(edit_version).to receive(:fetch_idfa_declaration).and_return(nil)
          expect(edit_version).to receive(:uses_idfa).and_return(false)

          expect(app).to receive(:update).with(attributes: {
            contentRightsDeclaration: "USES_THIRD_PARTY_CONTENT"
          })

          expect(edit_version).to receive(:create_app_store_version_submission)

          review_submitter.submit!(options)
        end
      end

      context 'IDFA' do
        it 'submission information with idfa false with no idfa' do
          options = {
            platform: Spaceship::ConnectAPI::Platform::IOS,
            submission_information: {
              add_id_info_uses_idfa: false
            }
          }

          expect(app).to receive(:get_edit_app_store_version).and_return(edit_version)
          expect(review_submitter).to receive(:select_build).and_return(selected_build)

          expect(selected_build).to receive(:uses_non_exempt_encryption).and_return(false)

          expect(edit_version).to receive(:fetch_idfa_declaration).and_return(nil)
          expect(edit_version).to receive(:update).with(attributes: { usesIdfa: false }).and_return(edit_version)
          expect(edit_version).to receive(:uses_idfa).and_return(false).exactly(2).times

          expect(edit_version).to receive(:create_app_store_version_submission)

          review_submitter.submit!(options)
        end

        it 'submission information with idfa false with existing idfa' do
          options = {
            platform: Spaceship::ConnectAPI::Platform::IOS,
            submission_information: {
              add_id_info_uses_idfa: false
            }
          }

          expect(app).to receive(:get_edit_app_store_version).and_return(edit_version)
          expect(review_submitter).to receive(:select_build).and_return(selected_build)

          expect(selected_build).to receive(:uses_non_exempt_encryption).and_return(false)

          expect(edit_version).to receive(:fetch_idfa_declaration).and_return(idfa_declaration)
          expect(edit_version).to receive(:update).with(attributes: { usesIdfa: false }).and_return(edit_version)
          expect(edit_version).to receive(:uses_idfa).and_return(false).exactly(2).times
          expect(idfa_declaration).to receive(:delete!)

          expect(edit_version).to receive(:create_app_store_version_submission)

          review_submitter.submit!(options)
        end

        it 'submission information with idfa true with no idfa' do
          options = {
            platform: Spaceship::ConnectAPI::Platform::IOS,
            submission_information: {
              add_id_info_uses_idfa: true,

              add_id_info_limits_tracking: true,
              add_id_info_serves_ads: true,
              add_id_info_tracks_install: true,
              add_id_info_tracks_action: true
            }
          }

          expect(app).to receive(:get_edit_app_store_version).and_return(edit_version)
          expect(review_submitter).to receive(:select_build).and_return(selected_build)

          expect(selected_build).to receive(:uses_non_exempt_encryption).and_return(false)

          expect(edit_version).to receive(:fetch_idfa_declaration).and_return(nil)
          expect(edit_version).to receive(:update).with(attributes: { usesIdfa: true }).and_return(edit_version)
          expect(edit_version).to receive(:uses_idfa).and_return(true).exactly(2).times

          expect(edit_version).to receive(:create_idfa_declaration).with(attributes: {
            honorsLimitedAdTracking: true,
            servesAds: true,
            attributesAppInstallationToPreviousAd: true,
            attributesActionWithPreviousAd: true
          })

          expect(edit_version).to receive(:create_app_store_version_submission)

          review_submitter.submit!(options)
        end

        it 'submission information with idfa true with existing idfa' do
          options = {
            platform: Spaceship::ConnectAPI::Platform::IOS,
            submission_information: {
              add_id_info_uses_idfa: true,

              add_id_info_limits_tracking: true,
              add_id_info_serves_ads: true,
              add_id_info_tracks_install: true,
              add_id_info_tracks_action: true
            }
          }

          expect(app).to receive(:get_edit_app_store_version).and_return(edit_version)
          expect(review_submitter).to receive(:select_build).and_return(selected_build)

          expect(selected_build).to receive(:uses_non_exempt_encryption).and_return(false)

          expect(edit_version).to receive(:fetch_idfa_declaration).and_return(idfa_declaration)
          expect(edit_version).to receive(:update).with(attributes: { usesIdfa: true }).and_return(edit_version)
          expect(edit_version).to receive(:uses_idfa).and_return(true).exactly(2).times

          expect(idfa_declaration).to receive(:update).with(attributes: {
            honorsLimitedAdTracking: true,
            servesAds: true,
            attributesAppInstallationToPreviousAd: true,
            attributesActionWithPreviousAd: true
          })

          expect(edit_version).to receive(:create_app_store_version_submission)

          review_submitter.submit!(options)
        end
      end
    end
  end
end
