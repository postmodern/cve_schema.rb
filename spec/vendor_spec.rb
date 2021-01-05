require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/vendor'

describe CVESchema::CVE::Vendor do
  describe "#initialize" do
    let(:vendor_name) { 'Example Co' }
    let(:product)     { [double(:Product)] }

    describe "required keywords" do
      context "when vendor_name: is not given" do
        it do
          expect {
            described_class.new(product: product)
          }.to raise_error(ArgumentError)
        end
      end

      context "when product: is not given" do
        it do
          expect {
            described_class.new(vendor_name: vendor_name)
          }.to raise_error(ArgumentError)
        end
      end
    end

    subject { described_class.new(vendor_name: vendor_name, product: product) }

    it "must set #vendor_name" do
      expect(subject.vendor_name).to eq(vendor_name)
    end

    it "must set #product" do
      expect(subject.product).to eq(product)
    end
  end

  describe ".from_json" do
    include_examples ".from_json"

    let(:json_node) do
      json_tree['affects']['vendor']['vendor_data'][0]
    end

    context '"vendor_name":' do
      it { expect(subject.vendor_name).to eq(json_node['vendor_name']) }
    end

    context '"product":' do
      it { expect(subject.product).to_not be_empty }
      it { expect(subject.product).to all(be_kind_of(CVESchema::CVE::Product)) }
    end
  end
end
