module CVESchema
  class InvalidJSON < StandardError
  end

  class MissingJSONKey < InvalidJSON

    def initialize(key)
      super("missing #{key.inspect} key")
    end

  end

  class UnknownJSONValue < InvalidJSON

    def initialize(key,value)
      super("unknown #{key.inspect} value: #{value.inspect}")
    end

  end
end
