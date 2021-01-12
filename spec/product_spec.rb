require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/product'

describe CVESchema::CVE::Product do
  let(:product_name) { 'Example' }
  let(:version)     { ['1.2.3', '2.0.0'] }

  describe "#initialize" do
    describe "required keywords" do
      it "must require a product_name:" do
        expect {
          described_class.new(version: version)
        }.to raise_error(ArgumentError)
      end
    end

    context "when a product_name: keyword is given" do
      subject { described_class.new(product_name: product_name) }

      it "must set #product_name" do
        expect(subject.product_name).to eq(product_name)
      end
    end

    context "when a verisons: keyword is given" do
      subject do
        described_class.new(product_name: product_name, version: version)
      end

      it "must set #product_name" do
        expect(subject.version).to eq(version)
      end
    end
  end

  describe ".load" do
    include_examples ".load"

    let(:json_node) do
      json_tree['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]
    end

    context '"product_name":' do
      it "must set #product_name" do
        expect(subject.product_name).to eq(json_node['product_name'])
      end
    end

    context '"version":' do
      it { expect(subject.version).to_not be_empty }
      it { expect(subject.version).to all(be_kind_of(CVESchema::CVE::Version)) }
    end
  end

  describe "#na?" do
    subject do
      described_class.new(product_name: product_name, version: version)
    end

    context "when value is 'n/a'" do
      let(:product_name) { 'n/a' }

      it { expect(subject.na?).to be(true) }
    end

    context "when value is not 'n/a'" do
      let(:product_name) { 'foo' }

      it { expect(subject.na?).to be(false) }
    end
  end
end
