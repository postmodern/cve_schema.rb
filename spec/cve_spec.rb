require 'spec_helper'
require 'shared_examples'
require 'cve_schema/cve'

describe CVESchema::CVE do
  describe "#initialize" do
    let(:data_type)    { :CVE   }
    let(:data_format)  { :MITRE }
    let(:data_version) { :"4.0" }
    let(:data_meta)    { double(:DataMeta) }

    context "required keywords" do
      context "when the data_type: keyword is not given" do
        it do
          expect { 
            described_class.new(
              data_format:  data_format,
              data_version: data_version,
              data_meta:    data_meta
            )
          }.to raise_error(ArgumentError)
        end
      end

      context "when the data_format: keyword is not given" do
        it do
          expect { 
            described_class.new(
              data_type:    data_type,
              data_version: data_version,
              data_meta:    data_meta
            )
          }.to raise_error(ArgumentError)
        end
      end

      context "when the data_version: keyword is not given" do
        it do
          expect { 
            described_class.new(
              data_type:   data_type,
              data_format: data_format,
              data_meta:   data_meta
            )
          }.to raise_error(ArgumentError)
        end
      end

      context "when the data_meta: keyword is not given" do
        it do
          expect { 
            described_class.new(
              data_type:    data_type,
              data_format:  data_format,
              data_version: data_version,
            )
          }.to raise_error(ArgumentError)
        end
      end
    end

    context "default values" do
      subject do
        described_class.new(
          data_type:    data_type,
          data_format:  data_format,
          data_version: data_version,
          data_meta:    data_meta
        )
      end

      it { expect(subject.affects).to eq(nil)       }
      it { expect(subject.configurations).to eq([]) }
      it { expect(subject.problemtype).to eq([])    }
      it { expect(subject.references).to eq([])     }
      it { expect(subject.description).to eq([])    }
      it { expect(subject.exploit).to eq([])        }
      it { expect(subject.credit).to eq([])         }
      it { expect(subject.impact).to eq(nil)        }
      it { expect(subject.solution).to eq([])       }
      it { expect(subject.source).to eq(nil)        }
      it { expect(subject.work_around).to eq([])    }
    end
  end

  describe ".from_json" do
    include_examples ".from_json"

    it "must return a new CVE object" do
      expect(subject).to be_kind_of(described_class)
    end

    context '"data_type":' do
      let(:json_value) { json_node['data_type'] }
      let(:expected)   { described_class::DATA_TYPES[json_value] }

      it "must convert and set #data_type" do
        expect(subject.data_type).to eq(expected)
      end
    end

    context '"data_format":' do
      let(:json_value) { json_node['data_format'] }
      let(:expected)   { described_class::DATA_FORMAT[json_value] }

      it "must convert and set #data_format" do
        expect(subject.data_format).to eq(expected)
      end
    end

    context '"data_version":' do
      let(:json_value) { json_node['data_version'] }
      let(:expected)   { described_class::DATA_VERSIONS[json_value] }

      it "must convert and set #data_version" do
        expect(subject.data_version).to eq(expected)
      end
    end

    context '"data_meta":' do
      let(:json_value) { json_node['CVE_data_meta'] }

      it "must convert the JSON Hash into a DataMeta objects and set #data_meta" do
        expect(subject.data_meta).to be_kind_of(described_class::DataMeta)
      end
    end

    context '"affects":' do
      context "when present" do
        describe "#affects" do
          it do
            expect(subject.affects).to be_kind_of(described_class::Affects)
          end
        end
      end

      context "when missing" do
        before { json_node.delete('affects') }

        describe "#affects" do
          it { expect(subject.affects).to be_nil }
        end
      end
    end

    context '"configuration":' do
      let(:cve_id) { 'CVE-2020-2005' }

      context "when present" do
        describe "#configuration" do
          it { expect(subject.configuration).to be_kind_of(Array) }
          it { expect(subject.configuration).to_not be_empty }
          it do
            expect(subject.configuration).to all(be_kind_of(described_class::Configuration))
          end
        end
      end

      context "when missing" do
        before { json_node.delete('configuration') }

        describe "#configuration" do
          it { expect(subject.configuration).to eq([]) }
        end
      end
    end

    context '"problemtype":' do
      context "when present" do
        describe "#problemtype" do
          it { expect(subject.problemtype).to be_kind_of(Array) }
          it { expect(subject.problemtype).to_not be_empty      }

          it do
            expect(subject.problemtype).to all(be_kind_of(described_class::ProblemType))
          end
        end
      end

      context "when missing" do
        before { json_node.delete('problemtype') }

        describe "#problemtype" do
          it { expect(subject.problemtype).to eq([]) }
        end
      end
    end

    context '"references":' do
      context "when present" do
        describe "#references" do
          it { expect(subject.references).to be_kind_of(Array) }
          it { expect(subject.references).to_not be_empty      }

          it do
            expect(subject.references).to all(be_kind_of(described_class::Reference))
          end
        end
      end

      context "when missing" do
        before { json_node.delete('references') }

        describe "#references" do
          it { expect(subject.references).to eq([]) }
        end
      end
    end

    context '"description":' do
      context "when present" do
        describe "#description" do
          it { expect(subject.description).to be_kind_of(Array) }
          it { expect(subject.description).to_not be_empty      }

          it do
            expect(subject.description).to all(be_kind_of(described_class::Description))
          end
        end
      end

      context "when missing" do
        before { json_node.delete('description') }

        describe "#description" do
          it { expect(subject.description).to eq([]) }
        end
      end
    end

    context '"exploit":' do
      let(:cve_id) { 'CVE-2020-2050' }

      context "when present" do
        describe "#exploit" do
          it { expect(subject.exploit).to be_kind_of(Array) }
          it { expect(subject.exploit).to_not be_empty      }

          it do
            expect(subject.exploit).to all(be_kind_of(described_class::Exploit))
          end
        end
      end

      context "when missing" do
        before { json_node.delete('exploit') }

        describe "#exploit" do
          it { expect(subject.exploit).to eq([]) }
        end
      end
    end

    context '"credit":' do
      context "when present" do
        describe "#credit" do
          it { expect(subject.credit).to be_kind_of(Array) }
          it { expect(subject.credit).to_not be_empty      }

          it do
            expect(subject.credit).to all(be_kind_of(described_class::Credit))
          end
        end
      end

      context "when missing" do
        before { json_node.delete('credit') }

        describe "#credit" do
          it { expect(subject.credit).to eq([]) }
        end
      end
    end

    context '"impact":' do
      context "when present" do
        describe "#impact" do
          it { expect(subject.impact).to be_kind_of(described_class::Impact) }
        end
      end

      context "when missing" do
        before { json_node.delete('impact') }

        describe "#impact" do
          it { expect(subject.impact).to be_nil }
        end
      end
    end

    context '"solution":' do
      context "when present" do
        describe "#solution" do
          it { expect(subject.solution).to be_kind_of(Array) }
          it { expect(subject.solution).to_not be_empty      }

          it do
            expect(subject.solution).to all(be_kind_of(described_class::Solution))
          end
        end
      end

      context "when missing" do
        before { json_node.delete('solution') }

        describe "#solution" do
          it { expect(subject.solution).to eq([]) }
        end
      end
    end

    context '"source":' do
      context "when present" do
        describe "#source" do
          it { expect(subject.source).to be_kind_of(described_class::Source) }
        end
      end

      context "when missing" do
        before { json_node.delete('source') }

        describe "#source" do
          it { expect(subject.source).to be_nil }
        end
      end
    end

    context '"work_around":' do
      let(:cve_id) { 'CVE-2020-2005' }

      context "when present" do
        describe "#work_around" do
          it { expect(subject.work_around).to be_kind_of(Array) }
          it { expect(subject.work_around).to_not be_empty      }

          it do
            expect(subject.work_around).to all(be_kind_of(described_class::WorkAround))
          end
        end
      end

      context "when missing" do
        before { json_node.delete('work_around') }

        describe "#work_around" do
          it { expect(subject.work_around).to eq([]) }
        end
      end
    end

    context '"timeline":' do
      let(:cve_id) { 'CVE-2020-2005' }

      context "when present" do
        describe "#timeline" do
          it { expect(subject.timeline).to be_kind_of(Array) }
          it { expect(subject.timeline).to_not be_empty      }

          it do
            expect(subject.timeline).to all(be_kind_of(described_class::Timeline))
          end
        end
      end

      context "when missing" do
        before { json_node.delete('timeline') }

        describe "#timeline" do
          it { expect(subject.timeline).to eq([]) }
        end
      end
    end
  end
end
