require 'spec_helper'
require 'cve_schema/cve/na'

describe "CVESchema::CVE::NA" do
  subject { CVESchema::CVE::NA }

  it "must equal 'n/a'" do
    expect(subject).to eq('n/a')
  end

  it "must be froozen" do
    expect(subject).to be_frozen
  end
end
