module CVESchema
  class CVE
    class Impact
      class CVSSv2

        class BM

          AV = {'L' => :L, 'A' => :A, 'N' => :N}

          # The Access Vector.
          #
          # @return [:L, :A, :N]
          attr_reader :av

          AC = {'H' => :H, 'M' => :M, 'L' => :L}

          # The Access Complexity.
          #
          # @return [:H, :M, :L]
          attr_reader :ac

          AU = {'M' => :M, 'S' => :S, 'N' => :N}

          # The Authentication
          #
          # @return [:M, :S, :N]
          attr_reader :au

          C = {'N' => :N, 'P' => :P, 'C' => :C}

          # The Confidentiality impact.
          # 
          # @return [:N, :P, :C]
          attr_reader :c

          I = {'N' => :N, 'P' => :P, 'C' => :C}

          # The Integrity impact.
          #
          # @return [:N, :P, :C]
          attr_reader :i

          A = {'N' => :N, 'P' => :P, 'C' => :C}

          # The Availability impact.
          #
          # @return [:N, :P, :C]
          attr_reader :a

          # The CVSSv2 Base Metrics Group score assuming all elements are present.
          #
          # @return [String]
          attr_reader :score

          def initialize(av: nil, ac: nil, au: nil, c: nil, i: nil, a: nil,
                         score: nil)
            @av = av
            @ac = ac
            @c = c
            @i = i
            @a = a
            @score = score
          end

          #
          # @param [Hash{String => Object}] json
          #
          # @return [self]
          #
          def self.from_json(json)
            new(
              av: AV[json['AV']],
              ac: AC[json['AC']],
              au: AU[json['AU']],
              c:  C[json['C']],
              i:  I[json['I']],
              a:  A[json['A']],

              score: json['SCORE']
            )
          end

        end

        # @return [BM, nil]
        attr_reader :bm

        class TM

          E = {'U' => :U, 'POC' => :POC, 'F' => :F, 'H' => :H, 'ND' => :ND}

          # Exploitability
          #
          # @return [:U, :POC, :F, :H, :ND]
          attr_reader :e

          RL = {'OF' => :OF, 'TF' => :TF, 'W' => :W, 'U' => :U, 'ND' => :ND}

          # Remediation Level.
          #
          # @return [:OF, :TF, :W, :U, :ND]
          attr_reader :rl

          RC = {'UC' => :UC, 'UR' => :UR, 'C' => :C, 'ND' => :ND}

          # Report Confidence.
          #
          # @return [:UC, :UR, :C, :ND]
          attr_reader :rc

          # The CVSSv2 Temporal Metrics Group score assuming all elements are present.
          #
          # @return [String, nil]
          attr_reader :score

          def initialize(e: nil, rl: nil, rc: nil, score: nil)
            @e = e
            @rl = rl
            @rc = rc
            @score = score
          end

          #
          # @param [Hash{String => Object}] json
          #
          # @return [self]
          #
          def self.from_json(json)
            new(
              e:  E[json['E']],
              rl: RL[json['RL']],
              rc: RC[json['RC']],

              score: json['SCORE']
            )
          end

        end

        # The Temporal Metrics Group.
        #
        # @return [TM, nil]
        attr_reader :tm

        class EM

          CDP = {
            'N' => :N,
            'L' => :L,
            'LM' => :LM,
            'MH' => :MH,
            'H' => :H,
            'ND' => :ND
          }

          # The Collateral Damage Potential.
          #
          # @return [:N, :L, :LM, :MH, :H, :ND]
          attr_reader :cdp

          TD = {'N' => :N, 'L' => :L, 'M' => :M, 'H' => :H, 'ND' => :ND}

          # The Target Distribution.
          # 
          # @return [:N, :L, :M, :H, :ND]
          attr_reader :td

          CR = {'L' => :L, 'M' => :M, 'H' => :H, 'ND' => :ND}

          # Security Requirements Confidentiality.
          #
          # @return [:L, :M, :H, :ND]
          attr_reader :cr

          IR = {'L' => :L, 'M' => :M, 'H' => :H, 'ND' => :ND}

          # Security Requirements Integrity.
          #
          # @return [:L, :M, :H, :ND]
          attr_reader :ir

          AR = {'L' => :L, 'M' => :M, 'H' => :H, 'ND' => :ND}

          # Security Requirements Availability.
          #
          # @return [:L, :M, :H, :ND]
          attr_reader :ar

          def initialize(cdp: nil, td: nil, cr: nil, ir: nil, ar: nil)
            @cdp = cdp
            @td  = td
            @cr  = cr
            @ir  = ir
            @ar  = ar
          end

          #
          # @param [Hash{String => Object}] json
          #
          # @return [self]
          #
          def self.from_json(json)
            new(
              cdp: CDP[json['CDP']],
              td:  TD[json['TD']],
              cr:  CR[json['CR']],
              ir:  IR[json['IR']],
              ar:  AR[json['AR']]
            )
          end

        end

        # @return [EM, nil]
        attr_reader :em

        #
        # Initializes the CVSSv2.
        #
        # @param [BM, nil] bm
        #
        # @param [TM, nil] tm
        #
        # @param [EM, nil] em
        #
        def initialize(bm: nil, tm: nil, em: nil)
          @bm = bm
          @tm = tm
          @em = em
        end

        #
        # @param [Hash{String => Object}] json
        #
        # @return [self]
        #
        def self.from_json(json)
          new(
            bm: json['BM'] && BM.from_json(json['BM']),
            tm: json['TM'] && TM.from_json(json['TM']),
            em: json['EM'] && EM.from_json(json['EM']),
          )
        end

      end
    end
  end
end
