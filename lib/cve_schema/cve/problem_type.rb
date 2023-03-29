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
      # Maps the parsed JSON to an Array of {Description} objects for
      # {#initialize}.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Array<Description>]
      #
      # @api semipublic
      #
      def self.from_json(json)
        json['description'].map(&Description.method(:load))
      end

      #
      # Loads the problem-type object from parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [ProblemType]
      #   The loaded problem-type object.
      #
      # @api semipublic
      #
      def self.load(json)
        new(from_json(json))
      end

    end
  end
end
