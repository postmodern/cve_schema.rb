require 'cve_schema/cve/has_lang_value'

module CVESchema
  class CVE
    #
    # Represents a solution object within the `"solutions"` JSON Array.
    #
    class Solution

      include HasLangValue

    end
  end
end
