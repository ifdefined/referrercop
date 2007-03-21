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

# Append this file's directory to the include path if it's not there already.
unless $:.include?(File.dirname(__FILE__)) ||
    $:.include?(File.expand_path(File.dirname(__FILE__)))
  $:.unshift(File.dirname(__FILE__)) 
end

# ReferrerCop includes
require 'referrercop/error'
require 'referrercop/config'
require 'referrercop/filter'
require 'referrercop/filter/apache-combined'
require 'referrercop/list'

module ReferrerCop

  #--
  # Constants
  #++
  
  # Array of paths that will be searched for the config file if it isn't
  # specified on the command line.
  CONFIG_PATHS = [
    '.',
    '~',
    '/etc',
    '/usr/local/etc',
    '/usr/local/share/referrercop',
    '/usr/share/referrercop',
    '/usr/etc',
  ]
  
  FILTER_CLASSES = [
    ApacheCombinedFilter,
    Filter,
  ]

  #REGEXPS = {
  #  :apache_combined          => /^\S+ - \S+ \[.+\] "[A-Z]+ \S+(?: \S+")? \d+ [\d-]+ "(.*)" ".*"$/i,
  #  :awstats_header           => /^AWSTATS DATA FILE /,
  #  :awstats_map              => /^BEGIN_MAP.*^END_MAP$/m,
  #  :awstats_pagerefs_extract => /^BEGIN_PAGEREFS.*?$.*?^(.*?)^END_PAGEREFS$/m,
  #  :awstats_pagerefs_replace => /^BEGIN_PAGEREFS.*?^END_PAGEREFS$/m,
  #  :awstats_url              => /^(https?:\/\/\S+)/i,
  #  :text_url                 => /^(https?:\/\/\S+)/i,
  #  :address                  => /^(?:https?:\/\/)?(?:www\d*\.)?(\S+?)\/?$/i,
  #}

  #--
  # Variables
  #++
  
  @blacklist = nil
  @whitelist = nil
  @cache     = {}
  @stats     = {}
  
  #--
  # Public Class Methods
  #++
  
  def self.each(input, type)
    filter = get_filter(input)
    
    if type == :ham
      filter.each {|url| yield url unless spam?(url) }
    elsif type == :spam
      filter.each {|url| yield url if spam?(url) }
    else
      raise ArgumentError, "invalid type: #{type}"
    end
  end
  
  def self.each_ham(input)
    each(input, :ham) {|url| yield url }
  end
  
  def self.each_spam(input)
    each(input, :spam) {|url| yield url }
  end
  
  # Filter _input_, writing only ham to _output_.
  def self.filter(input, output)
    filter = get_filter(input)
    filter.filter(output) {|url| spam?(url) }
    
    @stats = filter.stats.dup
  end
  
  # Returns an instance of the appropriate filter class for the given stream.
  def self.get_filter(input)
    # Determine which filter to use.
    filter_class = FILTER_CLASSES.detect {|filter| filter.filterable?(input) }    
    raise NoFilterError if filter_class.nil?
    
    $stderr.puts "Using filter #{filter_class}" if $VERBOSE
    
    return filter_class.new(input)
  end
  
  def self.load_blacklist(filename)
    @blacklist = File.exist?(filename) ? List.load_file(filename) : nil
  end
  
  def self.load_whitelist(filename)
    @whitelist = File.exist?(filename) ? List.load_file(filename) : nil
  end
  
  # Returns +true+ if _url_ is spam, +false+ otherwise.
  def self.spam?(url)
    @cache.fetch(url) do |url|
      return @cache[url] = false if !@whitelist.nil? && @whitelist[url]
      return @cache[url] = @blacklist[url]
    end
  end
  
end
