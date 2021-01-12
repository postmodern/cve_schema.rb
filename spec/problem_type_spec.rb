require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/problem_type'

describe CVESchema::CVE::ProblemType do
  describe "#initialize" do
    let(:description) { double(:description) }

    subject { described_class.new(description) }

    it "must set #description" do
      expect(subject.description).to be(description)
    end
  end

  describe ".load" do
    include_examples ".load"

    let(:json_node) { json_tree['problemtype']['problemtype_data'][0] }

    context '"description":' do
      it { expect(subject.description).to_not be_empty }
      it { expect(subject.description).to all(be_kind_of(CVESchema::CVE::Description)) }
    end
  end
end
