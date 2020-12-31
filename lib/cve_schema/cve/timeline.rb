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
      # Loads the timeline object from the parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [self]
      #
      def self.from_json(json)
        new(
          lang: json['lang'],
          time: Timestamp.parse(json['time']),
          value: json['value']
        )
      end

    end
  end
end
