module CVESchema
  class CVE
    #
    # Represents a reference object within the `"reference_data"` JSON Array.
    #
    class Reference

      # Reference URL.
      #
      # @return [String]
      attr_reader :url

      # Optional reference name.
      #
      # @return [String, nil]
      attr_reader :name

      REFSOURCES = {
        'MISC' => :MISC
      }
      REFSOURCES.default_proc = proc { |hash,key| key }

      # Optional reference source identifier.
      #
      # @return [:MISC, String, nil]
      attr_reader :refsource

      alias ref_source refsource

      #
      # Initializes the reference.
      #
      # @param [String] url
      #
      # @param [nil, String] name
      #
      # @param [nil, :MISC, String] refsource
      #
      def initialize(url: , name: nil, refsource: nil)
        @url = url
        @name = name
        @refsource = refsource
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
          url:  json['url'],
          name: json['name'],
          refsource: REFSOURCES[json['refsource']]
        }
      end

      #
      # Loads the reference from the parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Reference]
      #
      def self.load(json)
        new(**from_json(json))
      end

    end
  end
end
