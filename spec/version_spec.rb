require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/version'

describe CVESchema::CVE::Version do
  let(:version_value)    { '1.2.3' }
  let(:version_name)     { '1.2'   }
  let(:version_affected) { :"<"    }

  describe "#initialize" do
    describe "required keywords" do
      context "when the version_value: keyword is not given" do
        it do
          expect {
            described_class.new(version_name: version_name, version_affected: version_affected)
          }.to raise_error(ArgumentError)
        end
      end
    end

    context "when version_value: is given" do
      subject { described_class.new(version_value: version_value) }

      it "must set #version_value" do
        expect(subject.version_value).to eq(version_value)
      end
    end

    context "when version_name: is given" do
      subject do
        described_class.new(
          version_value: version_value,
          version_name: version_name
        )
      end

      it "must set #version_name" do
        expect(subject.version_name).to eq(version_name)
      end
    end

    context "when version_affected: is given" do
      subject do
        described_class.new(
          version_value: version_value,
          version_affected: version_affected
        )
      end

      it "must set #version_affected" do
        expect(subject.version_affected).to eq(version_affected)
      end
    end
  end

  describe ".load" do
    include_examples ".load"

    let(:json_node) do
      json_tree['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['version']['version_data'][0]
    end

    context '"version_value":' do
      it "must set #version_value" do
        expect(subject.version_value).to eq(json_node['version_value'])
      end
    end

    context '"version_name":' do
      it "must set #version_name" do
        expect(subject.version_name).to eq(json_node['version_name'])
      end
    end

    context '"version_affected":' do
      let(:json_value) { json_node['version_affected'] }
      let(:expected)   { described_class::VERSION_AFFECTED[json_value] }

      it "must set #version_affected" do
        expect(subject.version_affected).to eq(expected)
      end
    end
  end

  describe "#na?" do
    subject do
      described_class.new(
        version_value:    version_value,
        version_name:     version_name,
        version_affected: version_affected
      )
    end

    context "when value is 'n/a'" do
      let(:version_value) { 'n/a' }

      it { expect(subject.na?).to be(true) }
    end

    context "when value is not 'n/a'" do
      it { expect(subject.na?).to be(false) }
    end
  end
end
