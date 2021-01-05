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

  describe ".from_json" do
    include_examples ".from_json"

    let(:json_node) { json_tree['references']['reference_data'][0] }

    context '"refsource":' do
      it { expect(subject.refsource).to eq(json_node['refsource'].to_sym) }
    end

    context '"url":' do
      it { expect(subject.url).to eq(json_node['url']) }
    end

    context '"name":' do
      it { expect(subject.name).to eq(json_node['name']) }
    end
  end
end
