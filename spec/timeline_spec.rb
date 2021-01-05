require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/timeline'

describe CVESchema::CVE::Timeline do
  it { expect(described_class).to include(CVESchema::CVE::HasLangValue) }

  describe "#initialize" do
    let(:time)  { Time.now }
    let(:lang)  { 'eng' }
    let(:value) { 'Initial publication' }

    describe "required keywords" do
      context "when time: is not given" do
        it do
          expect {
            described_class.new(lang: lang, value: value)
          }.to raise_error(ArgumentError)
        end
      end

      context "when lang: is not given" do
        it do
          expect {
            described_class.new(time: time, value: value)
          }.to raise_error(ArgumentError)
        end
      end

      context "when value: is not given" do
        it do
          expect {
            described_class.new(time: time, lang: lang)
          }.to raise_error(ArgumentError)
        end
      end
    end

    subject do
      described_class.new(
        time: time,
        lang: lang,
        value: value
      )
    end

    it "must set #time" do
      expect(subject.time).to eq(time)
    end

    it "must set #lang" do
      expect(subject.lang).to eq(lang)
    end

    it "must set #value" do
      expect(subject.value).to eq(value)
    end
  end

  describe ".from_json" do
    include_examples ".from_json"

    let(:json_node) { json_tree['timeline'][0] }

    context '"time":' do
      let(:json_value) { json_node['time'] }
      let(:expected)   { CVESchema::CVE::Timestamp.parse(json_value) }

      it 'must parse the "time": value and set #time' do
        expect(subject.time).to eq(expected)
      end
    end

    context '"lang":' do
      it 'must parse the "lang": value and set #lang' do
        expect(subject.lang).to eq(json_node['lang'])
      end
    end

    context '"value":' do
      it 'must parse the "value": value and set #value' do
        expect(subject.value).to eq(json_node['value'])
      end
    end
  end
end
