# frozen_string_literal: true

module CVESchema
  class CVE
    class Impact
      class CVSSv3

        #
        # The Base Metric Group scoring information.
        #
        class BM

          AV = {'N' => :N, 'A' => :A, 'L' => :L, 'P' => :P}

          # The Attack Vector.
          #
          # @return [:N, :A, :L, :P]
          attr_reader :av

          AC = {'L' => :L, 'H' => :H}

          # The Attack Complexity.
          #
          # @return [:L, :H]
          attr_reader :ac

          PR = {'N' => :N, 'L' => :L, 'H' => :H}

          # The Privileges Required.
          #
          # @return [:N, :L, :H]
          attr_reader :pr

          UI = {'N' => :N, 'R' => :R}

          # The User Interaction.
          #
          # @return [:N, :R]
          attr_reader :ui

          S = {'U' => :U, 'C' => :C}

          # The Scope
          #
          # @return [:U, :C]
          attr_reader :s

          C = {'H' => :H, 'L' => :L, 'N' => :N}

          # The Confidentiality Impact.
          #
          # @return [:H, :L, :N]
          attr_reader :c

          I = {'H' => :H, 'L' => :L, 'N' => :N}

          # The Integrity Impact
          #
          # @return [:H, :L, :N]
          attr_reader :i

          A = {'H' => :H, 'L' => :L, 'N' => :N}

          # The Availability Impact
          #
          # @return [:H, :L, :N]
          attr_reader :a

          # The CVSSv3 score.
          #
          # @return [String]
          attr_reader :score

          #
          # Initializes the BM object.
          #
          def initialize(av: nil, ac: nil, pr: nil, ui: nil, s: nil, c: nil,
                         i: nil, a: nil, score: nil)
            @av = av
            @ac = ac
            @pr = pr
            @ui = ui
            @s  = s
            @c  = c
            @i  = i
            @a  = a

            @score = score
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
          def self.from_json(json)
            {
              av: AV[json['AV']],
              ac: AC[json['AC']],
              pr: PR[json['PR']],
              ui: UI[json['UI']],
              s:  S[json['S']],
              c:  C[json['C']],
              i:  I[json['I']],
              a:  A[json['A']],

              score: json['SCORE']
            }
          end

          #
          # Loads the BM object from the parsed JSON.
          #
          # @param [Hash{String => Object}] json
          #   The parsed JSON.
          #
          # @return [BM]
          #   The loaded BM object.
          #
          def self.load(json)
            new(**from_json(json))
          end

        end

        # @return [BM, nil]
        attr_reader :bm

        class TM

          E = {'X' => :X, 'H' => :H, 'F' => :F, 'P' => :P, 'U' => :U}

          # Exploit Code Maturity.
          #
          # @return [:X, :H, :F, :P, :U]
          attr_reader :e

          RL = {'X' => :X, 'U' => :U, 'W' => :W, 'T' => :T, 'O' => :O}

          # Remediation Level.
          #
          # @return [:X, :U, :W, :T, :O]
          attr_reader :rl

          RC = {'X' => :X, 'C' => :C, 'R' => :R, 'U' => :U}

          # Report Confidence.
          #
          # @return [:X, :C, :R, :U]
          attr_reader :rc

          #
          # Initializes the TM object.
          #
          def initialize(e: nil, rl: nil, rc: nil)
            @e  = e
            @rl = rl
            @rc = rc
          end

          #
          # Maps the parsed JSON to the Symbol Hash for {#initialize}.
          #
          # @param [Hash{String => Object}] json
          #   The parsed JSON.
          #
          # @return [Hash{Symbol => Object}]
          #   The mapped Symbol Hash.
          #
          def self.from_json(json)
            {
              e:  E[json['E']],
              rl: RL[json['RL']],
              rc: RC[json['RC']]
            }
          end

          #
          # Loads the TM object from the parsed JSON.
          #
          # @param [Hash{String => Object}] json
          #   The parsed JSON.
          #
          # @return [TM]
          #   The loaded TM object.
          #
          def self.load(json)
            new(**from_json(json))
          end

        end

        # @return [TM, nil]
        attr_reader :tm

        class EM

          CR = {'X' => :X, 'H' => :H, 'M' => :M, 'L' => :L}

          # Security Requirements Confidentiality.
          #
          # @return [:X, :H, :M, :L]
          attr_reader :cr

          IR = {'X' => :X, 'H' => :H, 'M' => :M, 'L' => :L}

          # Security Requirements Integrity.
          #
          # @return [:X, :H, :M, :L]
          attr_reader :ir

          AR = {'X' => :X, 'H' => :H, 'M' => :M, 'L' => :L}

          # Security Requirements Availability.
          #
          # @return [:X, :H, :M, :L]
          attr_reader :ar

          MAV = {'N' => :N, 'A' => :A, 'L' => :L, 'P' => :P}

          # The Modified Attack Vector.
          #
          # @return [:N, :A, :L, :P]
          attr_reader :mav

          MAC = {'L' => :L, 'H' => :H}

          # The Modified Attack Complexity.
          #
          # @return [:L, :H]
          attr_reader :mac

          MPR = {'N' => :N, 'L' => :L, 'H' => :H}

          # The Modified Privileges Required.
          #
          # @return [:N, :L, :H]
          attr_reader :mpr

          MUI = {'N' => :N, 'R' => :R}

          # The Modified User Interaction.
          #
          # @return [:N, :R]
          attr_reader :mui

          MS = {'U' => :S, 'C' => :C}

          # The Modified Scope.
          #
          # @return [:U, :C]
          attr_reader :ms

          MC = {'H' => :H, 'L' => :L, 'N' => :N}

          # The Modified Confidentiality Impact.
          #
          # @return [:H, :L, :N]
          attr_reader :mc

          MI = {'H' => :H, 'L' => :L, 'N' => :N}

          # The Modified Integrity Impact.
          #
          # @return [:H, :L, :N]
          attr_reader :mi

          MA = {'H' => :H, 'L' => :L, 'N' => :N}

          # The Modified Availability Impact.
          #
          # @return [:H, :L, :N]
          attr_reader :ma

          #
          # Initializes the EM object.
          #
          def initialize(cr: nil, ir: nil, ar: nil, mav: nil, mac: nil,
                         mpr: nil, mui: nil, ms: nil, mc: nil, mi: nil, ma: nil)
            @cr  = cr
            @ir  = ir
            @ar  = ar
            @mav = mav
            @mac = mac
            @mpr = mpr
            @mui = mui
            @ms  = ms
            @mc  = mc
            @mi  = mi
            @ma  = ma
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
          def self.from_json(json)
            {
              cr:  CR[json['CR']],
              ir:  IR[json['IR']],
              ar:  AR[json['AR']],
              mav: MAV[json['MAV']],
              mac: MAC[json['MAC']],
              mpr: MPR[json['MPR']],
              mui: MUI[json['MUI']],
              ms:  MS[json['MS']],
              mc:  MC[json['MC']],
              mi:  MI[json['MI']],
              ma:  MA[json['MA']]
            }
          end

          #
          # Loads the EM object from the parsed JSON.
          #
          # @param [Hash{String => Object}] json
          #   The parsed JSON.
          #
          # @return [EM]
          #   The loaded EM object.
          #
          def self.load(json)
            new(**from_json(json))
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
        # Maps the parsed JSON to a Symbol Hash for {#initialize}.
        #
        # @param [Hash{String => Object}] json
        #   The parsed JSON.
        #
        # @return [Hash{Symbol => Object}]
        #   The mapped Symbol Hash.
        #
        def self.from_json(json)
          {
            bm: json['BM'] && BM.load(json['BM']),
            tm: json['TM'] && TM.load(json['TM']),
            em: json['EM'] && EM.load(json['EM'])
          }
        end

        #
        # Loads the CVSSv3 object from the parsed JSON.
        #
        # @param [Hash{String => Object}] json
        #   The parsed JSON.
        #
        # @return [CVSSv3]
        #   the loaded CVSSv3 object.
        #
        def self.load(json)
          new(**from_json(json))
        end

      end
    end
  end
end
