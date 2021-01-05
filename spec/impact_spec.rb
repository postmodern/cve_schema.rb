require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/impact'

describe CVESchema::CVE::Impact do
  describe "#initialize" do
    context "when cvss_v2: is given" do
      let(:cvssv2) { double(:CVSSv2) }

      subject { described_class.new(cvssv2: cvssv2) }

      it "must set #cvssv2" do
        expect(subject.cvss_v2).to be(cvssv2)
      end
    end

    context "when cvssv3: is given" do
      let(:cvssv3) { double(:CVSSv3) }

      subject { described_class.new(cvssv3: cvssv3) }

      it "must set #cvss_v3" do
        expect(subject.cvss_v3).to be(cvssv3)
      end
    end
  end

  describe ".from_json" do
    include_examples ".from_json"

    let(:json_node) { json_tree['impact'] }

    context '"cvssv2":' do
      pending 'need to find a CVE with a "cvssv2": key' do
        it { expect(subject.cvss_v2).to be_kind_of(described_class::CVSSv2) }
      end
    end

    context '"cvssv3":' do
      pending 'need to find a CVE with a "cvssv3": key' do
        it { expect(subject.cvss_v3).to be_kind_of(described_class::CVSSv3) }
      end
    end
  end
end
