require 'cve_schema/cve/exceptions'
require 'time'

module CVESchema
  class CVE
    module Timestamp
      #
      # Parses a CVE timestamp (ISO 8601).
      #
      # @param [String] timestamp
      #   The raw timestamp String.
      #
      # @return [DateTime]
      #   The parsed ISO 8601 timestamp.
      #
      # @see https://github.com/CVEProject/cve-schema/blob/master/schema/v4.0/DRAFT-JSON-file-format-v4.md#timestamps
      #
      def self.parse(timestamp)
        DateTime.iso8601(timestamp)
      rescue Date::Error
        raise(InvalidJSON,"invalid ISO-8601 timestamp: #{timestamp.inspect}")
      end
    end
  end
end
