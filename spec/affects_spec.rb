require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/affects'

describe CVESchema::CVE::Affects do
  describe "#initialize" do
    let(:vendor) { double(:vendor) }

    subject { described_class.new(vendor) }

    it "must set #vendor" do
      expect(subject.vendor).to be(vendor)
    end
  end

  describe ".from_json" do
    include_examples ".from_json"

    let(:json_node) { json_tree['affects'] }

    context '"vendor":' do
      context '"vendor_data":' do
        it { expect(subject.vendor).to_not be_empty }
        it { expect(subject.vendor).to all(be_kind_of(CVESchema::CVE::Vendor)) }
      end
    end
  end
end
