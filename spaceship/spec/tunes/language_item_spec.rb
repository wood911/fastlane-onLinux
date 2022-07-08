describe Spaceship::Tunes::LanguageItem do
  before do
    Spaceship::Tunes.login
  end

  describe "language code inspection" do
    it "prints out all languages with their values" do
      str = Spaceship::Application.all.first.edit_version.description.inspect
      expect(str).to eq("German: My title\nEnglish: Super Description here\n")
    end

    it "localCode is also used for language keys" do
      # details.name uses `localCode` instead of `languages`
      keys = Spaceship::Application.all.first.details.name.keys
      expect(keys).to eq(["en-US", "de-DE"])
    end

    it "localCode is also used for inspect method" do
      # details.name uses `localeCode` instead of `languages`
      inspect_string = Spaceship::Application.all.first.details.name.inspect
      expect(inspect_string).to eq("en-US: Updated by fastlane\nde-DE: why new itc 2\n")
    end

    it "localCode is also used for get_lang method" do
      # details.name uses `localeCode` instead of `languages`
      english_name = Spaceship::Application.all.first.details.name["en-US"]
      expect(english_name).to eq("Updated by fastlane")
    end

    it "ensure test data is setup as expected" do
      # details.name uses `localeCode` instead of `languages`, so no nodes should exist for `languages`
      original_array = Spaceship::Application.all.first.details.name.original_array
      locale_node = original_array.flat_map { |value| value["localeCode"] }
      languages_node = original_array.each_with_object([]) do |value, languages|
        language = value["languages"]
        languages << language unless language.nil?
      end

      expect(locale_node).to eq(["en-US", "de-DE"])
      expect(languages_node).to be_empty
    end
  end
end
