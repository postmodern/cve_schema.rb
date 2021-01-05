require 'spec_helper'
require 'cve_schema/cve/solution'

describe CVESchema::CVE::Solution do
  it { expect(described_class).to include(CVESchema::CVE::HasLangValue) }
end
