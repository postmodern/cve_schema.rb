require 'spec_helper'
require 'cve_schema/cve/has_lang_value'

describe CVESchema::CVE::HasLangValue do
  let(:klass) do
    Class.new.tap do |klass|
      klass.send :include, described_class
    end
  end

  let(:lang)  { :en       }
  let(:value) { 'foo bar' }

  describe "#initialize" do
    subject { klass }

    describe "required keywords" do
      it "must require the lang: keyword" do
        expect {
          subject.new(value: value)
        }.to raise_error(ArgumentError)
      end

      it "must require the value: keyword" do
        expect {
          subject.new(lang: lang)
        }.to raise_error(ArgumentError)
      end
    end
  end

  describe ".from_json" do
    subject { klass }

    let(:json) do
      {
        'lang'  => lang.to_s,
        'value' => value
      }
    end

    subject { klass.from_json(json) }

    it "must return an instance of the including Class" do
      expect(subject).to be_kind_of(klass)
    end

    it "must set #lang" do
      expect(subject.lang).to eq(lang)
    end

    it "must set #value" do
      expect(subject.value).to eq(value)
    end
  end
end
