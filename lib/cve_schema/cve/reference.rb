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
      # Loads the reference from the parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [self]
      #
      def self.from_json(json)
        new(
          url:  json['url'],
          name: json['name'],
          refsource: REFSOURCES[json['refsource']]
        )
      end

    end
  end
end
