require 'spec_helper'
require 'cve_schema/cve/credit'

describe CVESchema::CVE::Credit do
  it { expect(described_class).to include(CVESchema::CVE::HasLangValue) }
end
