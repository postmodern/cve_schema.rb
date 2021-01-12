require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/vendor'

describe CVESchema::CVE::Vendor do
  let(:vendor_name) { 'Example Co' }
  let(:product)     { [double(:Product)] }

  describe "#initialize" do
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

  describe ".load" do
    include_examples ".load"

    let(:json_node) do
      json_tree['affects']['vendor']['vendor_data'][0]
    end

    context '"vendor_name":' do
      it "must set #vendor_name" do
        expect(subject.vendor_name).to eq(json_node['vendor_name'])
      end
    end

    context '"product":' do
      it { expect(subject.product).to_not be_empty }
      it { expect(subject.product).to all(be_kind_of(CVESchema::CVE::Product)) }
    end
  end

  describe "#na?" do
    subject { described_class.new(vendor_name: vendor_name, product: product) }

    context "when value is 'n/a'" do
      let(:vendor_name) { 'n/a' }

      it { expect(subject.na?).to be(true) }
    end

    context "when value is not 'n/a'" do
      let(:vendor_name) { 'foo' }

      it { expect(subject.na?).to be(false) }
    end
  end
end
