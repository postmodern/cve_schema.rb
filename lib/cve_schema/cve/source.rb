module CVESchema
  class CVE
    #
    # Represents the `"source"` JSON object.
    #
    class Source

      # @return [Array<String>, nil]
      attr_reader :defect

      DISCOVERY = {
        'INTERNAL' => :INTERNAL,
        'EXTERNAL' => :EXTERNAL,
        'USER'     => :USER,
        'UNKNOWN'  => :UNKNOWN
      }

      # @return [:INTERNAL, :EXTERNAL, :USER, :UNKNOWN]
      attr_reader :discovery

      # @return [String, nil]
      attr_reader :advisory

      #
      # Initializes the source object.
      #
      # @param [Array<String>, nil] defect
      #
      # @param [:INTERNAL, :EXTERNAL, :USER, :UNKNOWN] discovery
      #
      # @param [String, nil] advisory
      #
      def initialize(discovery: , defect: nil, advisory: nil)
        @defect    = defect
        @discovery = discovery
        @advisory  = advisory
      end

      #
      # Maps the parsed JSON to a Symbol Hash for {#initialize}.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Hash{Symbol => Object}]
      #   The mapped Symbol Hash.
      #
      def self.from_json(json)
        {
          defect:    json['defect'],
          discovery: DISCOVERY[json['discovery']],
          advisory:  json['advisory']
        }
      end

      #
      # Loads the source from the parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Source]
      #   The loaded source object.
      #
      # @api semipublic
      #
      def self.load(json)
        new(**from_json(json))
      end

    end
  end
end
