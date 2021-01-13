require 'cve_schema/cve/timestamp'
require 'cve_schema/cve/has_lang_value'

module CVESchema
  class CVE
    #
    # Represents a timeline entry in the `"timeline"` JSON Array.
    #
    class Timeline

      include HasLangValue

      # The time of the timeline event.
      #
      # @return [DateTime]
      attr_reader :time

      #
      # Initializes the timeline object.
      #
      # @param [DateTime] time
      #
      def initialize(time: , **kargs)
        super(**kargs)

        @time = time
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
      # @api semipublic
      #
      def self.from_json(json)
        {
          lang: json['lang'],
          time: Timestamp.parse(json['time']),
          value: json['value']
        }
      end

      #
      # Loads the timeline object from the parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Timeline]
      #   The loaded timeline object.
      #
      # @api semipublic
      #
      def self.load(json)
        new(**from_json(json))
      end

    end
  end
end
