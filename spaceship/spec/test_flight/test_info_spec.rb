require 'spec_helper'

describe Spaceship::TestFlight::TestInfo do
  let(:test_info) do
    Spaceship::TestFlight::TestInfo.new([
                                          {
                                            'locale' => 'en-US',
                                            'description' => 'en-US description',
                                            'feedbackEmail' => 'enUS@email.com',
                                            'whatsNew' => 'US News',
                                            'marketingUrl' => 'www.markingurl.com/en',
                                            'privacyPolicyUrl' => 'www.privacypolicy.com/en'
                                          },
                                          {
                                            'locale' => 'de-DE',
                                            'description' => 'de-DE description',
                                            'feedbackEmail' => 'deDE@email.com',
                                            'whatsNew' => 'German News',
                                            'marketingUrl' => 'www.markingurl.com/de',
                                            'privacyPolicyUrl' => 'www.privacypolicy.com/de'
                                          },
                                          {
                                            'locale' => 'de-AT',
                                            'description' => 'de-AT description',
                                            'feedbackEmail' => 'deAT@email.com',
                                            'whatsNew' => 'Austrian News',
                                            'marketingUrl' => 'www.markingurl.com/at',
                                            'privacyPolicyUrl' => 'www.privacypolicy.com/at'
                                          }
                                        ])
  end

  let(:mock_client) { double('MockClient') }

  before do
    # Use a simple client for all data models
    allow(Spaceship::TestFlight::Base).to receive(:client).and_return(mock_client)
    allow(mock_client).to receive(:team_id).and_return('')
  end

  it 'gets the value from the first locale' do
    expect(test_info.feedback_email).to eq('enUS@email.com')
    expect(test_info.description).to eq('en-US description')
    expect(test_info.whats_new).to eq('US News')
    expect(test_info.marketing_url).to eq('www.markingurl.com/en')
    expect(test_info.privacy_policy_url).to eq('www.privacypolicy.com/en')
  end

  it 'sets values to all locales' do
    test_info.whats_new = 'News!'
    expect(test_info.raw_data.all? { |locale| locale['whatsNew'] == 'News!' }).to eq(true)
  end

  it 'copies its contents' do
    new_test_info = test_info.deep_copy
    expect(new_test_info.object_id).to_not(eq(test_info.object_id))

    # make sure it is a deep copy, but the contents are the same
    new_test_info.raw_data.zip(test_info.raw_data).each do |sub_array|
      new_item = sub_array.first
      item = sub_array.last
      expect(new_item.object_id).to_not(eq(item.object_id))
      expect(new_item.to_s).to eq(item.to_s)
    end
  end
end
