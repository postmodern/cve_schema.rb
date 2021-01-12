require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve/impact/cvss_v3'

describe CVESchema::CVE::Impact::CVSSv3 do
  describe "#initialize" do
    context "when given the bm: keyword" do
      let(:bm) { double(:BM) }

      subject { described_class.new(bm: bm) }

      it "must set #bm" do
        expect(subject.bm).to be(bm)
      end
    end

    context "when given the tm: keyword" do
      let(:tm) { double(:TM) }

      subject { described_class.new(tm: tm) }

      it "must set #tm" do
        expect(subject.tm).to be(tm)
      end
    end

    context "when given the em: keyword" do
      let(:em) { double(:EM) }

      subject { described_class.new(em: em) }

      it "must set #em" do
        expect(subject.em).to be(em)
      end
    end
  end

  describe ".load" do
    include_examples ".load"

    let(:cve_id) { 'CVE-2020-4700' }
    let(:json_node) { json_tree['impact']['cvssv3'] }

    context '"BM":' do
      it { expect(subject.bm).to be_kind_of(described_class::BM) }
    end

    context '"TM":' do
      it { expect(subject.bm).to be_kind_of(described_class::BM) }
    end

    context '"EM":' do
      pending 'need to find a CVE containing "EM":' do
        it { expect(subject.bm).to be_kind_of(described_class::BM) }
      end
    end
  end

  describe described_class::BM do
    describe "#initialize" do
    end

    describe ".load" do
      include_examples ".load"

      let(:cve_id) { 'CVE-2020-4700' }
      let(:json_node) { json_tree['impact']['cvssv3']['BM'] }

      {'AV' => :av, 'AC' => :ac, 'PR' => :pr, 'UI' => :ui, 'S' => :s, 'C' => :c, 'I' => :i, 'A' => :a}.each do |json_key,attr|
        context "\"#{json_key}\":" do
          it "must set ##{attr}" do
            expect(subject.send(attr)).to eq(json_node[json_key].to_sym)
          end
        end
      end

      context '"SCORE":' do
        it "must set #score" do
          expect(subject.score).to eq(json_node['SCORE'])
        end
      end
    end
  end

  describe described_class::TM do
    describe "#initialize" do
    end

    describe ".load" do
      include_examples ".load"

      let(:cve_id) { 'CVE-2020-4700' }
      let(:json_node) { json_tree['impact']['cvssv3']['TM'] }

      {'E' => :e, 'RL' => :rl, 'RC' => :rc}.each do |json_key,attr|
        context "\"#{json_key}\":" do
          it "must set ##{attr}" do
            expect(subject.send(attr)).to eq(json_node[json_key].to_sym)
          end
        end
      end
    end
  end

  describe described_class::EM do
    describe "#initialize" do
    end

    describe ".load" do
      include_examples ".load"

      let(:cve_id) { 'CVE-2020-4700' }
      let(:json_node) { json_tree['impact']['cvssv3']['EM'] }

      pending 'need to find a CVE containing "EM":'
    end
  end
end
