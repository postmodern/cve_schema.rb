require 'cve_schema/cve/description'

module CVESchema
  class CVE
    #
    # Represents an element within the `"problemtype_data"` JSON Array.
    #
    class ProblemType

      # @return [Array<Description>]
      attr_reader :description

      alias descriptions description

      #
      # Initializes the problem-type object.
      #
      # @param [Array<Description>] description
      #
      def initialize(description)
        @description = description
      end

      #
      # Loads the problem-type object from parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [self]
      #
      def self.from_json(json)
        new(
          json['description'].map(&Description.method(:from_json))
        )
      end

    end
  end
end
