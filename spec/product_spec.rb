require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/product'

describe CVESchema::CVE::Product do
  let(:product_name) { 'Example' }
  let(:versions)     { ['1.2.3', '2.0.0'] }

  describe "#initialize" do
    describe "required keywords" do
      it "must require a product_name:" do
        expect {
          described_class.new(versions: versions)
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
        described_class.new(product_name: product_name, versions: versions)
      end

      it "must set #product_name" do
        expect(subject.versions).to eq(versions)
      end
    end
  end

  describe ".from_json" do
    include_examples ".from_json"

    let(:json_node) do
      json_tree['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]
    end

    context '"product_name":' do
      it "must set #product_name" do
        expect(subject.product_name).to eq(json_node['product_name'])
      end
    end

    context '"versions":' do
      it { expect(subject.versions).to_not be_empty }
      it { expect(subject.versions).to all(be_kind_of(CVESchema::CVE::Version)) }
    end
  end

  describe "#na?" do
    subject do
      described_class.new(product_name: product_name, versions: versions)
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
