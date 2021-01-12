require 'spec_helper'

require 'json'

RSpec.shared_examples ".from_json" do
  let(:cve_id) { 'CVE-2020-1994' }
  let(:file)   { File.expand_path("../fixtures/#{cve_id}.json",__FILE__) }

  let(:json_tree) { JSON.parse(File.read(file)) }
  let(:json_node) { json_tree }

  subject { described_class.from_json(json_node) }
end

RSpec.shared_examples ".load" do
  include_examples ".from_json"

  subject { described_class.load(json_node) }
end
