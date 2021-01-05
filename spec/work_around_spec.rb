require 'spec_helper'
require 'cve_schema/cve/work_around'

describe CVESchema::CVE::WorkAround do
  it { expect(described_class).to include(CVESchema::CVE::HasLangValue) }
end
