require 'spec_helper'
require 'cve_schema/cve/id'

describe CVESchema::CVE::ID do
  let(:year)   { '2021' }
  let(:number) { '9999' }

  describe "#initialize" do
    subject { described_class.new(year,number) }

    it "must set #year" do
      expect(subject.year).to eq(year)
    end

    it "must set #number" do
      expect(subject.number).to eq(number)
    end
  end

  describe ".parse" do
    subject { described_class }

    context "when given a valid CVE" do
      let(:id) { "CVE-#{year}-#{number}" }

      subject { super().parse(id) }

      it "muset extract the year component" do
        expect(subject.year).to eq(year)
      end

      it "must extract the number component" do
        expect(subject.number).to eq(number)
      end
    end

    context "when given an invalid CVE" do
      let(:id) { 'XYZ-123-abc' }

      it do
        expect { subject.parse(id) }.to raise_error(ArgumentError)
      end
    end
  end

  subject { described_class.new(year,number) }

  describe "#==" do
    context "when given a non-ID object" do
      let(:other) { Object.new }

      it { expect(subject == other).to be(false) }
    end

    context "when given another ID object" do
      context "and the other ID has the same year" do
        context "but a different number" do
          let(:other) { described_class.new(year,'0000') }

          it { expect(subject == other).to be(false) }
        end

        context "and the same number" do
          let(:other) { described_class.new(year,number) }

          it { expect(subject == other).to be(true) }
        end
      end

      context "and the other ID has a different year" do
        context "but a different number" do
          let(:other) { described_class.new('3000','0000') }

          it { expect(subject == other).to be(false) }
        end

        context "and the same number" do
          let(:other) { described_class.new('3000',number) }

          it { expect(subject == other).to be(false) }
        end
      end
    end
  end

  describe "#to_s" do
    it "must convert the ID back into a valid CVE string" do
      expect(subject.to_s).to eq("CVE-#{year}-#{number}")
    end
  end
end
