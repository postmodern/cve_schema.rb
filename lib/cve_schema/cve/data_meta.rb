# frozen_string_literal: true

require 'cve_schema/exceptions'
require 'cve_schema/cve/id'
require 'cve_schema/cve/timestamp'

module CVESchema
  class CVE
    #
    # Represents the `"CVE_data_meta"` JSON object.
    #
    class DataMeta

      # The CVE ID.
      #
      # @return [ID]
      attr_reader :id

      # The assigner's email address.
      #
      # @return [String]
      attr_reader :assigner

      # Date last updated.
      #
      # @return [DateTime, nil]
      attr_reader :updated

      # @return [Integer, nil]
      attr_reader :serial

      # Date requested.
      #
      # @return [DateTime, nil]
      attr_reader :date_requested

      # Date assigned.
      #
      # @return [DateTime, nil]
      attr_reader :date_assigned

      # Date published publically.
      #
      # @return [DateTime, nil]
      attr_reader :date_public

      # Requester email address.
      #
      # @return [String, nil]
      attr_reader :requester

      # List of IDs that replaced the CVE.
      #
      # @return [Array<ID>, nil]
      attr_reader :replaced_by

      STATES = {
        'PUBLIC'      => :PUBLIC,
        'RESERVED'    => :RESERVED,
        'REPLACED_BY' => :REPLACED_BY,
        'SPLIT_FROM'  => :SPLIT_FROM,
        'MERGED_TO'   => :MERGED_TO,
        'REJECT'      => :REJECT
      }

      # @return [:PUBLIC, :RESERVED, :REPLACED_BY, :SPLIT_FROM, :MERGED_TO, nil]
      attr_reader :state

      # @return [String, nil]
      attr_reader :title

      #
      # Initializes the data-meta object.
      #
      # @param [ID] id
      #
      # @param [String] assigner
      #
      # @param [DateTime, nil] updated
      #
      # @param [Integer, nil] serial
      #
      # @param [DateTime, nil] date_requested
      #
      # @param [DateTime, nil] date_assigned
      #
      # @param [DateTime, nil] date_public
      #
      # @param [String, nil] requester
      #
      # @param [Array<ID>, nil] replaced_by
      #
      # @param [:PUBLIC, :RESERVED, :REPLACED_BY, :SPLIT_FROM, :MERGED_TO, nil] state
      #
      # @param [String, nil] title
      def initialize(id: , assigner: , updated: nil,
                                       serial: nil,
                                       date_requested: nil,
                                       date_assigned: nil,
                                       date_public: nil,
                                       requester: nil,
                                       replaced_by: nil,
                                       state: nil,
                                       title: nil)
        @id       = id
        @assigner = assigner

        @updated        = updated
        @serial         = serial
        @date_requested = date_requested
        @date_assigned  = date_assigned
        @date_public    = date_public
        @requester      = requester
        @replaced_by    = replaced_by
        @state          = state
        @title          = title
      end

      #
      # Maps the parsed JSON to a Symbol Hash for {#initialize}.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Hash{Symbol => Object}]
      #   The Symbol Hash.
      #
      # @raise [MissingJSONKey]
      #   The `"ID"` or `"ASSIGNER"` JSON keys were missing.
      #
      # @raise [UnknownJSONValue]
      #   The `"STATE"` JSON value was unknown.
      #
      # @api semipublic
      #
      def self.from_json(json)
        {
          id: if (id = json['ID'])
                ID.parse(id)
              else
                raise(MissingJSONKey,'ID')
              end,

          assigner: json['ASSIGNER'] || raise(MissingJSONKey,'ASSIGNER'),

          updated: json['UPDATED'] && Timestamp.parse(json['UPDATED']),
          serial:  json['SERIAL'],
          date_requested: json['DATE_REQUESTED'] && Timestamp.parse(json['DATE_REQUESTED']),
          date_assigned: json['DATE_ASSIGNED'] && Timestamp.parse(json['DATE_ASSIGNED']),
          date_public: json['DATE_PUBLIC'] && Timestamp.parse(json['DATE_PUBLIC']),
          requester: json['REQUESTER'],
          replaced_by: json['REPLACED_BY'] && json['REPLACED_BY'].split(/,\s*/).map { |id| ID.parse(id) },
          state: if json['STATE']
                   STATES.fetch(json['STATE']) do
                     raise(UnknownJSONValue,'STATE',json['STATE'])
                   end
                 end,
          title: json['TITLE']
        }
      end

      #
      # Loads the data-meta object from the parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [self]
      #   The loaded data-meta object.
      #
      # @raise [MissingJSONKey]
      #   The `"ID"` or `"ASSIGNER"` JSON keys were missing.
      #
      # @raise [UnknownJSONValue]
      #   The `"STATE"` JSON value was unknown.
      #
      # @api semipublic
      #
      def self.load(json)
        new(**from_json(json))
      end

    end
  end
end
