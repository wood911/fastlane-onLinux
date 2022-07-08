describe FastlaneCore do
  describe FastlaneCore::ConfigItem do
    describe "ConfigItem sensitivity testing" do
      it "is code_gen_sensitive if just sensitive" do
        item = FastlaneCore::ConfigItem.new(key: :tacos,
                                     short_option: "-t",
                                     description: "tacos are the best, amirite?",
                                     default_value: "taco secret",
                                     sensitive: true)
        expect(item.code_gen_sensitive).to be(true)
        expect(item.code_gen_default_value).to be(nil)
      end

      it "is not code_gen_sensitive by default" do
        item = FastlaneCore::ConfigItem.new(key: :tacos,
                                     short_option: "-t",
                                     default_value: "taco secret",
                                     description: "tacos are the best, amirite?")
        expect(item.code_gen_sensitive).to be(false)
        expect(item.code_gen_default_value).to eq("taco secret")
      end

      it "can be code_gen_sensitive even if not sensitive" do
        item = FastlaneCore::ConfigItem.new(key: :tacos,
                                     short_option: "-t",
                                     default_value: "taco secret",
                                     description: "tacos are the best, amirite?",
                                     code_gen_sensitive: true)
        expect(item.code_gen_sensitive).to be(true)
        expect(item.code_gen_default_value).to be(nil)
      end

      it "must be code_gen_sensitive even if defined false, when sensitive is true" do
        item = FastlaneCore::ConfigItem.new(key: :tacos,
                                     short_option: "-t",
                                     description: "tacos are the best, amirite?",
                                     sensitive: true,
                                     code_gen_sensitive: false)
        expect(item.code_gen_sensitive).to be(true)
        expect(item.sensitive).to be(true)
      end

      it "uses code_gen_default_value when default value exists" do
        item = FastlaneCore::ConfigItem.new(key: :tacos,
                                     short_option: "-t",
                                     default_value: "taco secret",
                                     code_gen_default_value: "nothing",
                                     description: "tacos are the best, amirite?",
                                     code_gen_sensitive: true)
        expect(item.code_gen_sensitive).to be(true)
        expect(item.code_gen_default_value).to eq("nothing")

        item = FastlaneCore::ConfigItem.new(key: :tacos,
                                     short_option: "-t",
                                     default_value: "taco secret",
                                     code_gen_default_value: "nothing",
                                     description: "tacos are the best, amirite?")
        expect(item.code_gen_sensitive).to be(false)
        expect(item.code_gen_default_value).to eq("nothing")

        # Don't override default value
        expect(item.default_value).to eq("taco secret")
      end
    end

    describe "ConfigItem input validation" do
      it "doesn't raise an error if everything's valid" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     short_option: "-f",
                                     description: "foo")
        expect(result.key).to eq(:foo)
        expect(result.short_option).to eq("-f")
        expect(result.description).to eq("foo")
      end

      describe "raises an error if short option is invalid" do
        it "long string" do
          expect do
            FastlaneCore::ConfigItem.new(key: :foo,
                                short_option: :f,
                                 description: "foo")
          end.to raise_error("short_option for key :foo must of type String")
        end

        it "long string" do
          expect do
            FastlaneCore::ConfigItem.new(key: :foo,
                                short_option: "-abc",
                                 description: "foo")
          end.to raise_error("short_option for key :foo must be a string of length 1")
        end
      end

      describe "raises an error for invalid description" do
        it "raises an error if the description ends with a dot" do
          expect do
            FastlaneCore::ConfigItem.new(key: :foo,
                                short_option: "-f",
                                 description: "foo.")
          end.to raise_error("Do not let descriptions end with a '.', since it's used for user inputs as well for key :foo")
        end
      end
    end

    describe "ConfigItem Boolean type auto_convert value" do
      it "auto convert to 'true' Boolean type if default value is 'yes' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "yes")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(true)
      end

      it "auto convert to 'true' Boolean type if default value is 'YES' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "YES")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(true)
      end

      it "auto convert to 'true' Boolean type if default value is 'true' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "true")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(true)
      end

      it "auto convert to 'true' Boolean type if default value is 'TRUE' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "TRUE")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(true)
      end

      it "auto convert to 'true' Boolean type if default value is 'on' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "on")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(true)
      end

      it "auto convert to 'true' Boolean type if default value is 'ON' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "ON")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(true)
      end

      it "auto convert to 'false' Boolean type if default value is 'no' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "no")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(false)
      end

      it "auto convert to 'false' Boolean type if default value is 'NO' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "NO")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(false)
      end

      it "auto convert to 'false' Boolean type if default value is 'false' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "false")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(false)
      end

      it "auto convert to 'false' Boolean type if default value is 'FALSE' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "FALSE")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(false)
      end

      it "auto convert to 'false' Boolean type if default value is 'off' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "off")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(false)
      end

      it "auto convert to 'false' Boolean type if default value is 'OFF' string" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                     type: FastlaneCore::Boolean,
                                     default_value: "OFF")
        auto_convert_value = result.auto_convert_value(result.default_value)
        expect(auto_convert_value).to be(false)
      end
    end

    describe "ConfigItem Array type input validation" do
      it "doesn't raise an error if value is Array type" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                              default_value: ["foo1", "foo2"])
        expect(UI).not_to receive(:user_error)
        result.ensure_array_type_passes_validation(result.default_value)
      end

      it "doesn't raise an error if value is String type" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                              default_value: "foo1")
        expect(UI).not_to receive(:user_error)
        result.ensure_array_type_passes_validation(result.default_value)
      end

      it "doesn't raise an error if value is comma-separated String type" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                              default_value: "foo1,foo2")
        expect(UI).not_to receive(:user_error)
        result.ensure_array_type_passes_validation(result.default_value)
      end

      it "does raise an error if value is Boolean type" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                              default_value: true)
        expect do
          result.ensure_array_type_passes_validation(result.default_value)
        end.to raise_error("'foo' value must be either `Array` or `comma-separated String`! Found TrueClass instead.")
      end

      it "does raise an error if value is Hash type" do
        result = FastlaneCore::ConfigItem.new(key: :foo,
                                              default_value: {})
        expect do
          result.ensure_array_type_passes_validation(result.default_value)
        end.to raise_error("'foo' value must be either `Array` or `comma-separated String`! Found Hash instead.")
      end
    end
  end
end
