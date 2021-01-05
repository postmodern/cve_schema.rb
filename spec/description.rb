require 'spec_helper'
require 'cve_schema/cve/description'

describe CVESchema::CVE::Description do
  it { expect(described_class).to include(CVESchema::CVE::HasLangValue) }

  describe "#na?" do
    let(:lang) { 'eng' }

    subject { described_class.new(lang: lang, value: value) }

    context "when value is 'n/a'" do
      let(:value) { 'n/a' }

      it { expect(subject.na?).to be(true) }
    end

    context "when value is not 'n/a'" do
      let(:value) { 'foo' }

      it { expect(subject.na?).to be(false) }
    end
  end
end
