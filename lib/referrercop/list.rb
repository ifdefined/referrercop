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

# stdlib includes
require 'digest/sha1'
require 'uri'

module ReferrerCop
  
  class List
    include Enumerable
    
    REGEXP_COMMENT = /#.*$/
    REGEXP_REGEXP  = /^\/(.+)\/$/
    REGEXP_URL     = URI.regexp(['http', 'https'])
    REGEXP_WWW     = /^www\./i
    
    #--
    # Public Class Methods
    #++
    
    # Returns a new List instance representing the list contained in the
    # specified file.
    def self.load_file(filename)
      return File.open(filename, 'r') {|file| List.new(file) }
    end
    
    #--
    # Public Instance Methods
    #++
    
    attr_reader :sha1, :size
    
    # Parses and compiles the given IO stream as a list (such as a blacklist or
    # whitelist) and returns an instance of the List class representing the
    # parsed list.
    def initialize(io)
      unless io.is_a?(IO)
        raise ArgumentError, "expected IO, got #{io.class}"
      end
      
      @entries = {}
      @regexps = []
      @size    = 0
      
      io.rewind
      
      # Calculate the SHA1 digest of the list.
      digest = Digest::SHA1.new
      
      while data = io.read(8192)
        digest << data
      end
      
      @sha1 = digest.hexdigest
      
      # If a compiled list has already been cached, load it instead of
      # recompiling.
      if Config::CACHE_PATH
        cache_file = File.join(Config::CACHE_PATH,
            "#{self.class.to_s.downcase}_compiled.refcop")
        
        if File.exist?(cache_file)
          cache = {}        
          File.open(cache_file, 'rb') {|file| cache = Marshal.load(file) }
          
          if @sha1 == cache[:sha1]
            @entries = cache[:entries]
            @regexps = cache[:regexps]
            @size    = cache[:size]
            return
          end
        end
      end
      
      # Compile the list.
      io.rewind
      
      line_num = 0
      
      begin
        io.each do |line|
          line_num += 1
          
          # Strip comments.
          line.sub!(REGEXP_COMMENT, '')
          line.strip!
          
          # Skip empty lines.
          next if line.empty?
          
          @size += 1
          
          case line
            when REGEXP_URL
              url = URI.parse(line.slice(REGEXP_URL))
              @entries[url.host + url.path] = true
              
            when REGEXP_REGEXP
              @regexps << Regexp.new($1)
            
            else
              @entries[line] = true
          end
        end
      rescue => e
        raise ListParseError, "list parse error at line #{line_num}: #{e}"
      end
      
      # Cache the compiled list.
      if Config::CACHE_PATH
        File.open(cache_file, 'wb') do |file|
          Marshal.dump({
              :sha1    => @sha1,
              :entries => @entries,
              :regexps => @regexps,
              :size    => @size
          }, file)
        end
      end
    end
    
    # Returns +true+ if _key_ is in the list, +false+ otherwise.
    def [](key)
      begin
        uri  = URI.parse(key)
        host = uri.host
        url  = uri.host + uri.path.chomp('/')
        
        host.slice!(REGEXP_WWW)
      rescue => e
        host = nil
        url  = key.strip.chomp('/')
      end
      
      return (!host.nil? && @entries.include?(host)) || 
          @entries.include?(url) || 
          @regexps.any?{|regexp| url =~ regexp }
    end
    
    alias has_key? []
    alias include? []
    alias key? []
    alias member? []
    alias fetch []
    
    def each
      @regexps.each {|regexp| yield regexp }
      @entries.each {|entry| yield entry }
    end
    
    def each_entry
      @entries.each {|entry| yield entry }
    end
    
    def each_regexp
      @regexps.each {|regexp| yield regexp }
    end
  end
  
  class Blacklist < List; end;
  class Whitelist < List; end;
  
end