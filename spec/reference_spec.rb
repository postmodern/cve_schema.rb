require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/reference'

describe CVESchema::CVE::Reference do
  describe "#initialize" do
    let(:url)       { 'https://example.com/foo.html' }
    let(:name)      { 'foo' }
    let(:refsource) { :MISC }

    context "required keywords" do
      context "when the url: keyword is not given" do
        it do
          expect {
            described_class.new(name: name, refsource: refsource)
          }.to raise_error(ArgumentError)
        end
      end
    end

    subject { described_class.new(url: url) }

    it "must set #url" do
      expect(subject.url).to be(url)
    end

    context "when the name: keyword is given" do
      subject { described_class.new(url: url, name: name) }

      it "must set #name" do
        expect(subject.name).to be(name)
      end
    end

    context "when the refsource: keyword is given" do
      subject { described_class.new(url: url, refsource: refsource) }

      it "must set #refsource" do
        expect(subject.refsource).to be(refsource)
      end
    end
  end

  describe ".load" do
    include_examples ".load"

    let(:json_node) { json_tree['references']['reference_data'][0] }

    context '"refsource":' do
      let(:json_value) { json_node['refsource'] }
      let(:expected)   { json_value.to_sym      }

      it 'must parse the "refsource": value and set #refsource' do
        expect(subject.refsource).to eq(expected)
      end
    end

    context '"url":' do
      it "muset set #url" do
        expect(subject.url).to eq(json_node['url'])
      end
    end

    context '"name":' do
      it "must set #name" do
        expect(subject.name).to eq(json_node['name'])
      end
    end
  end
end
