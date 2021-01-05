require 'spec_helper'
require 'cve_schema/cve/configuration'

describe CVESchema::CVE::Configuration do
  it { expect(described_class).to include(CVESchema::CVE::HasLangValue) }
end
