require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/data_meta'

describe CVESchema::CVE::DataMeta do
  describe "#initialize" do
    let(:id)       { CVESchema::CVE::ID.parse('CVE-2021-9999') }
    let(:assigner) { 'foo@example.com' }

    describe "required keywords" do
      context "when id: is not given" do
        it do
          expect {
            described_class.new(assigner: assigner)
          }.to raise_error(ArgumentError)
        end
      end

      context "when assigner: is not given" do
        it do
          expect {
            described_class.new(id: id)
          }.to raise_error(ArgumentError)
        end
      end
    end

    context "when updated: is given" do
      let(:updated) { Time.now }

      subject do
        described_class.new(id: id, assigner: assigner, updated: updated)
      end

      it "must set #updated" do
        expect(subject.updated).to eq(updated)
      end
    end
  end

  describe ".from_json" do
    include_examples ".from_json"

    let(:json_node) { json_tree['CVE_data_meta'] }

    context '"ID":' do
      it 'must parse the "ID": CVE ID and set #id' do
        expect(subject.id).to eq(CVESchema::CVE::ID.parse(json_node['ID']))
      end
    end

    context '"ASSIGNER":' do
      it "must set #assigner" do
        expect(subject.assigner).to eq(json_node['ASSIGNER'])
      end
    end

    context '"UPDATED":' do
      pending 'need to find a CVE with the "UPDATED": key' do
        let(:expected) do
          CVESchema::CVE::Timestamp.parse(json_node['UPDATED'])
        end

        it 'must parse the "UPDATED": Timestamp and set #updated' do
          expect(subject.updated).to eq(expected)
        end
      end
    end

    context '"SERIAL":' do
      pending 'need to find a CVE with the "SERIAL": key' do
        it "must set #serial" do
          expect(subject.serial).to eq(json_node['SERIAL'])
        end
      end
    end

    context '"DATE_REQUESTED":' do
      pending 'need to find a CVE with the "DATE_REQUESTED": key' do
        let(:expected) do
          CVESchema::CVE::Timestamp.parse(json_node['DATE_REQUESTED'])
        end

        it 'must parse the "DATE_REQUESTED": Timestamp and set #date_requested' do
          expect(subject.date_requested).to eq(expected)
        end
      end
    end

    context '"DATE_ASSIGNED":' do
      pending 'need to find a CVE with the "DATE_ASSIGNED": key' do
        let(:expected) do
          CVESchema::CVE::Timestamp.parse(json_node['DATE_ASSIGNED'])
        end

        it 'must parse the "DATE_ASSIGNED": Timestamp and set #date_assigned' do
          expect(subject.date_assigned).to eq(expected)
        end
      end
    end

    context '"DATE_PUBLIC":' do
      let(:expected) do
        CVESchema::CVE::Timestamp.parse(json_node['DATE_PUBLIC'])
      end

      it 'must parse the "DATE_PUBLIC": Timestamp and set #date_public' do
        expect(subject.date_public).to eq(expected)
      end
    end

    context '"STATE":' do
      it 'must parse the "STATE": value and set #state' do
        expect(subject.state).to eq(json_node['STATE'].to_sym)
      end
    end

    context '"TITLE":' do
      it "must set #title" do
        expect(subject.title).to eq(json_node['TITLE'])
      end
    end

    context '"REQUESTER":' do
      pending 'need to find a CVE with the "REQUESTED": key' do
        it "must set #serial" do
          expect(subject.serial).to eq(json_node['REQUESTER'])
        end
      end
    end

    context '"REPLACED_BY":' do
      pending 'need to find a CVE with the "REPLACED_BY": key' do
        let(:expected) do
          json_node['REPLACED_BY'].split(',').map(&CVESchema::CVE::ID.method(:parse))
        end

        it 'must parse the "REPLACED_BY": String of IDs and set #replaced_by' do
          expect(subject.replaced_by).to eq(expected)
        end
      end
    end
  end
end
