require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/source'

describe CVESchema::CVE::Source do
  describe "#initialize" do
    let(:defect)    { ['PAN-123391'] }
    let(:discovery) { :USER }
    let(:advisory)  { 'VENDOR-12345' }

    context "required keywords" do
      context "when the discovery: keyword is not given" do
        it do
          expect {
            described_class.new(defect: defect, advisory: advisory)
          }.to raise_error(ArgumentError)
        end
      end
    end

    subject do
      described_class.new(discovery: discovery)
    end

    it "must set #discovery" do
      expect(subject.discovery).to be(discovery)
    end

    context "when the defect: keyword is given" do
      subject do
        described_class.new(
          discovery: discovery,
          defect:    defect
        )
      end

      it "must set #defect" do
        expect(subject.defect).to be(defect)
      end
    end

    context "when the advisory: keyword is given" do
      subject do
        described_class.new(
          discovery: discovery,
          advisory:  advisory
        )
      end

      it "must set #advisory" do
        expect(subject.advisory).to be(advisory)
      end
    end
  end

  describe ".from_json" do
    include_examples ".from_json"

    let(:json_node) { json_tree['source'] }

    context '"defect":' do
      it "must set #defect" do
        expect(subject.defect).to eq(json_node['defect'])
      end
    end

    context '"discovery":' do
      let(:json_value) { json_node['discovery'] }
      let(:expected)   { json_value.to_sym      }

      it "must set #discovery" do
        expect(subject.discovery).to eq(expected.to_sym)
      end
    end

    context '"advisory":' do
      pending 'need to find a CVE with the "advisory": key' do
        it "must set #advisory" do
          expect(subject.advisory).to eq(json_node['advisory'])
        end
      end
    end
  end
end
