#--
# Copyright (c) 2007 Ryan Grove <ryan@wonko.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   * Neither the name of this project nor the names of its contributors may be
#     used to endorse or promote products derived from this software without
#     specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#++

module ReferrerCop
  
  # The base Filter class filters text files containing one URL per line.
  class Filter
    include Enumerable
   
    REGEXP_URL = /^\s*(https?:\/\/\S+)/i
    
    #--
    # Public Class Methods
    #++
    
    # Returns +true+ if the given IO stream is filterable by this filter,
    # +false+ otherwise.
    def self.filterable?(io)
      unless io.is_a?(IO)
        raise ArgumentError, "expected IO, got #{io.class}"
      end
      
      return true
    end
    
    #--
    # Public Instance Methods
    #++
    
    attr_reader :stats
    
    def initialize(input)
      unless input.is_a?(IO)
        raise ArgumentError, "invalid input: expected IO, got #{input.class}"
      end
      
      unless self.class.filterable?(input)
        raise UnsupportedInputFormatError
      end
      
      @input = input
      
      clear_stats
    end
    
    # Yields each URL in the input stream to the block.
    def each # :yields: url
      @input.rewind
      
      @input.each do |line|
        if line =~ REGEXP_URL
          yield $1
        end
      end
    end
    
    # Executes the block for each URL in the input stream. If the block
    # evaluates to +true+, the URL is considered spam and will be removed from
    # the output stream.
    def filter(output) # :yields: url
      unless output.is_a?(IO)
        raise ArgumentError, "invalid output: expected IO, got #{output.class}"
      end
      
      clear_stats      
      @input.rewind

      start_time = Time.now.to_f
      
      @input.each do |line|
        @stats[:processed] += 1
        
        unless line =~ REGEXP_URL
          @stats[:invalid] += 1
          output.puts(line)
          next
        end
        
        if yield $1
          @stats[:spam] += 1
        else
          @stats[:ham] += 1
          output.puts(line)
        end
      end
      
      end_time = Time.now.to_f
      
      @stats[:time] = end_time - start_time
      @stats[:lines_per_second] = @stats[:time] > 0 ? 
          (@stats[:processed] / @stats[:time]).round : 0
    end
    
    #--
    # Private Instance Methods
    #++
    
    private
    
    def clear_stats
      @stats = {
        :processed        => 0,
        :ham              => 0,
        :spam             => 0,
        :invalid          => 0,
        :time             => 0.0,
        :lines_per_second => 0
      }
    end
    
  end

end
