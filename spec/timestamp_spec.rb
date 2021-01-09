require 'spec_helper'
require 'cve_schema/cve/timestamp'

describe CVESchema::CVE::Timestamp do
  describe ".parse" do
    context "when given a ISO 8601 timestamp" do
      let(:timestamp) { '2020-05-13T16:00:00.000Z' }

      it "must parse it" do
        expect(subject.parse(timestamp)).to eq(DateTime.parse(timestamp))
      end
    end

    context "when given a non-ISO 8601 timestamp" do
      let(:timestamp) { '2021-01-05 00:35:14 -0800' }

      it do
        expect {
          subject.parse(timestamp)
        }.to raise_error(CVESchema::CVE::InvalidJSON)
      end
    end
  end
end
