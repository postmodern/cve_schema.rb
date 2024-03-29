module CVESchema
  class CVE
    #
    # Represents a CVE ID (ex: `CVE-2021-1234`).
    #
    class ID

      # The year the CVE ID was assigned.
      #
      # @return [String]
      attr_reader :year

      # The CVE number.
      #
      # @return [String]
      attr_reader :number

      #
      # Initializes the CVE ID.
      #
      # @param [String] year
      #   The year the CVE ID was assigned.
      #
      # @param [String] number
      #   The CVE number.
      #
      def initialize(year,number)
        @year   = year
        @number = number
      end

      #
      # Parses the CVE ID.
      #
      # @param [String] id
      #   The CVE ID string.
      #
      # @raise [ArgumentError]
      #   The given ID was not a valid CVE.
      #
      def self.parse(id)
        cve, year, number = id.split('-',3)

        unless cve == 'CVE'
          raise(ArgumentError,"invalid CVE #{id.inspect}")
        end

        new(year,number)
      end

      #
      # Compares the ID with another ID.
      #
      # @param [ID] other
      #   The other ID.
      #
      # @return [Boolean]
      #   Indicates whether the IDs match.
      #
      def ==(other)
        self.class == other.class && (
          @year   == other.year && 
          @number == other.number
        )
      end

      #
      # Converts the CVE ID back into a String.
      #
      # @return [String]
      #   The full CVE ID (ex: `CVE-2021-1234`).
      #
      def to_s
        "CVE-#{@year}-#{@number}"
      end

    end
  end
end
