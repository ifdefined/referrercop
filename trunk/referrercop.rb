#!/usr/local/bin/ruby
#
# = ReferrerCop
# Parses an Apache log file or AWStats data file and filters out entries for
# referrers that are known spammers.
#
# Visit http://wonko.com/software/referrercop for news, usage examples, and
# updates. Blacklists can be downloaded from http://referrercop.org/.
#
# Version::   1.2.0 (?)
# Author::    Ryan Grove (mailto:ryan@wonko.com)
# Copyright:: Copyright (c) 2006 Ryan Grove
# License::   ReferrerCop is open source software distributed under the terms
#             of the GNU General Public License.
#
# == Dependencies
# * Ruby[http://ruby-lang.org/] 1.8.2+
#
# == Usage
#       referrercop [-f | -i | -n | -s] [options] [<file> ...]
#       referrercop -u <url> [options]
#       referrercop -U [options]
#       referrercop {-h | -V}
#
# Modes:
#  -f, --filter             Filter the specified files (or standard input if no
#                           files are specified), sending the results to
#                           standard output. This is the default mode.
#  -i, --in-place           Filter the specified files in place, replacing each
#                           file with the filtered version. A backup of the
#                           original file will be created with a .bak extension.
#  -n, --extract-ham        Extract ham (nonspam) URLs from the input data and
#                           send them to standard output. Duplicates will be
#                           suppressed.
#  -s, --extract-spam       Extract spam URLs from the input data and send
#                           them to standard output. Duplicates will be
#                           suppressed.
#  -u, --url <url>          Test the specified URL.
#  -U, --update             Check for an updated version of the default
#                           blacklist and download it if available.
#
# Options:
#  -b, --blacklist <file>   Blacklist to use instead of the default list.
#  -c, --config <file>      Use the specified config file.
#  -v, --verbose            Print verbose status and statistical info to stderr.
#  -w, --whitelist <file>   Whitelist to use instead of the default list.
#
# Information:
#  -h, --help               Display usage information (this message).
#  -V, --version            Display version information.
#
# :title: ReferrerCop Documentation
#
# $Id:$

require 'digest/sha1'
require 'fileutils'
require 'net/http'
require 'optparse'
require 'ostruct'
require 'time'
require 'uri'
require 'yaml'
require 'zlib'

module ReferrerCopConfig

  @default = {
    :BLACKLIST_FILE  => '/usr/local/share/referrercop/blacklist.refcop',
    :WHITELIST_FILE  => '/usr/local/share/referrercop/whitelist.refcop',
    :CACHE_PATH      => '/tmp',
    :UPDATE_URL      => 'http://referrercop.org/blacklists/referrer-standard.txt.gz',
    :UPDATE_SHA1_URL => 'http://referrercop.org/blacklists/referrer-standard.sha1',
  }

  def self.const_missing(name)
    @default[name]
  end

  def self.load_config(config_file)
    if File.exist?(config_file)
      load config_file
    else
      abort "Config file not found: #{config_file}"
    end

  rescue ScriptError => e
    abort "Configuration error in #{e}"

  rescue NameError => e
    abort "Configuration error in #{config_file}: #{e}"
  end

end # module ReferrerCopConfig

module ReferrerCop

  APP_NAME      = 'ReferrerCop'
  APP_VERSION   = '1.2.0'

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

  # Common regular expressions used throughout the application.
  REGEXPS = {
    :apache_combined          => /^\S+ - \S+ \[.+\] "[A-Z]+ \S+(?: \S+")? \d+ [\d-]+ "(.*)" ".*"$/i,
    :awstats_header           => /^AWSTATS DATA FILE /,
    :awstats_map              => /^BEGIN_MAP.*^END_MAP$/m,
    :awstats_pagerefs_extract => /^BEGIN_PAGEREFS.*?$.*?^(.*?)^END_PAGEREFS$/m,
    :awstats_pagerefs_replace => /^BEGIN_PAGEREFS.*?^END_PAGEREFS$/m,
    :awstats_url              => /^(https?:\/\/\S+)/i,
    :text_url                 => /^(https?:\/\/\S+)/i,
    :address                  => /^(?:https?:\/\/)?(?:www\d*\.)?(\S+?)\/?$/i,
  }

  # Cache to hold URLs that have already been examined. This speeds up
  # filtering by about three zillion percent.
  @cache = Hash.new

  # Options that can be set from the command line.
  @options = OpenStruct.new({
    'blacklist'   => nil,                   # blacklist filename
    'config_file' => nil,                   # config filename
    'mode'        => :filter,               # program operation mode
    'url'         => nil,                   # url passed on the command line
    'whitelist'   => nil                    # whitelist filename
  })

  # Processing statistics.
  @stats = OpenStruct.new({
    'invalid' => 0,                         # number of malformed/corrupt lines
    'lines'   => 0,                         # total number of lines processed
    'ham'     => 0,                         # number of nonspam lines
    'spam'    => 0,                         # number of spam lines
    'start'   => 0,                         # timestamp when filtering began
    'end'     => 0                          # timestamp when filtering ended
  })

  # -- Methods ----------------------------------------------------------------

  #
  # Determines the format of <em>input</em> and extracts URLs of the specified
  # type.
  #
  # <em>type</em> should be either <tt>:ham</tt> or <tt>:spam</tt>.
  #
  def self.extract(input, type)
    begin
      case input_type(input)
        when :apache_combined
          $stderr.puts "Input type: Apache combined log file" if $VERBOSE
          return extract_apache_combined(input, type)

        when :awstats
          $stderr.puts "Input type: AWStats data file" if $VERBOSE
          return extract_awstats(input, type)

        when :text
          $stderr.puts "Input type: Text" if $VERBOSE
          return extract_text(input, type)
      end

    rescue => e
      abort("Error: #{e}")
    end
  end # extract

  #
  # Extracts URLs of the specified type (<tt>:ham</tt> or <tt>:spam</tt>) from
  # an Apache combined log file.
  #
  def self.extract_apache_combined(input, type)
    extracted = Array.new

    input.each do |line|
      @stats.lines += 1

      # Skip over invalid lines.
      unless line =~ REGEXPS[:apache_combined]
        @stats.invalid += 1
        next
      end

      # Examine the URL.
      if $1 != '-' && spam?($1)
        @stats.spam += 1
        extracted << $1 if type == :spam
      else
        @stats.ham += 1
        extracted << $1 if type == :ham
      end
    end

    extracted.delete('-')
    extracted.delete('')

    return extracted.uniq
  end # extract_apache_combined

  def self.extract_awstats(input, type)
    data      = input.read
    extracted = Array.new

    # Extract referrers.
    referrers = data.slice!(REGEXPS[:awstats_pagerefs_extract], 1).strip

    # Extract URLs.
    referrers.each_line do |line|
      @stats.lines += 1

      # Skip over invalid lines.
      unless line =~ REGEXPS[:awstats_url]
        @stats.invalid += 1
        next
      end

      # Examine the URL.
      if spam?($1)
        @stats.spam += 1
        extracted << $1 if type == :spam
      else
        @stats.ham += 1
        extracted << $1 if type == :ham
      end
    end

    extracted.delete('-')
    extracted.delete('')

    return extracted.uniq
  end # extract_awstats

  def self.extract_text(input, type)
    extracted = Array.new

    input.each do |line|
      @stats.lines += 1

      # Skip over invalid lines.
      unless line =~ REGEXPS[:text_url]
        @stats.invalid += 1
        next
      end

      # Examine the URL.
      if spam?($1)
        @stats.spam += 1
        extracted << $1 if type == :spam
      else
        @stats.ham += 1
        extracted << $1 if type == :ham
      end
    end

    extracted.delete('-')
    extracted.delete('')

    return extracted.uniq
  end # extract_text

  #
  # Determines the format of <em>input</em> and filters it for referrer spam. The
  # filtered data will be sent to <em>output</em>.
  #
  def self.filter(input, output = $stdout)
    begin
      case input_type(input)
        when :apache_combined
          $stderr.puts "Input type: Apache combined log file" if $VERBOSE
          filter_apache_combined(input, output)

        when :awstats
          $stderr.puts "Input type: AWStats data file" if $VERBOSE
          filter_awstats(input, output)

        when :text
          $stderr.puts "Input type: Text" if $VERBOSE
          filter_text(input, output)
      end

    rescue => e
      abort("Error: #{e}")
    end
  end # filter

  #
  # Parses and filters Apache combined log entries from <em>input</em>. The
  # filtered log entries will be sent to <em>output</em>.
  #
  def self.filter_apache_combined(input, output = $stdout)
    input.each do |line|
      @stats.lines += 1

      # Skip over invalid lines.
      unless line =~ REGEXPS[:apache_combined]
        @stats.invalid += 1
        output.puts line
        next
      end

      # Examine the URL.
      if $1 != '-' && spam?($1)
        @stats.spam += 1
      else
        @stats.ham += 1
        output.puts line
      end
    end
  end # filter_apache_combined

  #
  # Parses and filters AWStats data from <em>input</em>. The filtered data will
  # be sent to <em>output</em>.
  #
  def self.filter_awstats(input, output = $stdout)
    data = input.read

    # Remove the section map (AWStats will regenerate it during the next update).
    data.slice!(REGEXPS[:awstats_map])

    # Extract referrers.
    referrers = data.slice!(REGEXPS[:awstats_pagerefs_extract], 1).strip

    # Filter referrers.
    filtered = Array.new

    referrers.each_line do |line|
      @stats.lines += 1

      # Skip over invalid lines.
      unless line =~ REGEXPS[:awstats_url]
        @stats.invalid += 1
        filtered << line
        next
      end

      # Examine the URL.
      if spam?($1)
        @stats.spam += 1
      else
        @stats.ham += 1
        filtered << line
      end
    end

    # We have to be careful about newlines or AWStats will go all apeshit.
    if filtered.length > 0
      referrers = filtered.join('').strip + "\n"
    else
      referrers = ''
    end

    output.puts data.gsub(REGEXPS[:awstats_pagerefs_replace],
      "BEGIN_PAGEREFS #{filtered.length}\n#{referrers}END_PAGEREFS")
  end # filter_awstats

  #
  # Parses and filters <em>input</em> as a list of URLs (one per line). The
  # filtered URLs will be sent to <em>output</em>.
  #
  def self.filter_text(input, output = $stdout)
    input.each do |line|
      @stats.lines += 1

      # Skip over invalid lines.
      unless line =~ REGEXPS[:text_url]
        @stats.invalid += 1
        output.puts line
        next
      end

      # Examine the URL.
      if spam?($1)
        @stats.spam += 1
      else
        @stats.ham += 1
        output.puts line
      end
    end
  end # filter_text

  #
  # Examines <em>input</em> and returns its type. The following input types are
  # supported:
  #
  # [:apache_combined] Apache combined log file.
  # [:awstats]         AWStats data file.
  # [:text]            Unrecognized format (assumed to be a list of URLs).
  #
  def self.input_type(input = ARGF)
    case input.gets
      when REGEXPS[:apache_combined]
        type = :apache_combined

      when REGEXPS[:awstats_header]
        type = :awstats

      else
        type = :text
    end

    input.rewind

    return type
  end # input_type

  #
  # Loads a whitelist or blacklist from the specified file. The <em>type</em>
  # argument should be either <code>:blacklist</code> or
  # <code>:whitelist</code>.
  #
  def self.load_list(filename, type)
    unless [:blacklist, :whitelist].include?(type)
      raise "Invalid list type: #{type}"
    end

    compiled_list           = Hash.new
    compiled_list[:hash]    = ''
    compiled_list[:regexps] = Array.new

    unless File.exist?(filename)
      if type == :whitelist
        return compiled_list
      else
        raise "File not found: #{filename}"
      end
    end

    $stderr.puts "Using #{type} #{filename}" if $VERBOSE

    # Read the list and calculate its SHA1 hash.
    list      = File.read(filename)
    list_hash = Digest::SHA1.hexdigest(list)

    # Check to see if we've cached a compiled version of the list.
    unless ReferrerCopConfig::CACHE_PATH.nil?
      cache_file = File.join(ReferrerCopConfig::CACHE_PATH, "#{type}_compiled.refcop")

      if File.exist?(cache_file)
        begin
          compiled_list = Marshal.load(File.read(cache_file))
          #compiled_list = YAML.load_file(cache_file)

          if compiled_list[:hash] == list_hash
            $stderr.puts "Loaded compiled #{type} from cache." if $VERBOSE
            return compiled_list
          end

        rescue => e
          $stderr.puts "Error loading #{type} from cache." if $VERBOSE
        end
      end
    end

    # No cached version; compile the list.
    compiled_list           = Hash.new
    compiled_list[:hash]    = ''
    compiled_list[:regexps] = Array.new

    length = 0

    list.each do |line|
      # Strip comments.
      line.sub!(/#.*/, '')
      line.strip!

      # Skip empty lines.
      next if line.empty?

      length += 1

      if line =~ /^\/(.+)\/$/
        compiled_list[:regexps] << Regexp.new($1, Regexp::IGNORECASE)
      else
        compiled_list[:regexps] << Regexp.new(Regexp.escape(line),
          Regexp::IGNORECASE)
      end
    end

    # Cache the compiled list if possible.
    compiled_list[:hash] = list_hash

    unless ReferrerCopConfig::CACHE_PATH.nil?
      begin
        File.open(cache_file, 'w') do |file|
          #YAML.dump(compiled_list, file)
          file.write(Marshal.dump(compiled_list))
        end

      rescue => e
        $stderr.puts "Unable to create cache file: #{cache_file}" if $VERBOSE
      end
    end

    $stderr.puts "Compiled #{length} #{type} entries" if $VERBOSE

    return compiled_list
  end # load_list

  #
  # Loads <em>filename</em> as a blacklist. If <em>filename</em> is *nil* and a
  # blacklist exists at one of the paths specified in CONFIG_PATHS, that
  # blacklist will be loaded.
  #
  def self.load_blacklist(filename = nil)
    if filename == nil
      @options.blacklist = ReferrerCopConfig::BLACKLIST_FILE
    end

    begin
      return load_list(@options.blacklist, :blacklist)
    rescue => e
      abort e
    end
  end # load_blacklist

  #
  # Loads <em>filename</em> as a whitelist. If <em>filename</em> is *nil* and a
  # whitelist exists at one of the paths specified in CONFIG_PATHS, that
  # whitelist will be loaded.
  #
  def self.load_whitelist(filename = nil)
    if filename == nil
      @options.whitelist = ReferrerCopConfig::WHITELIST_FILE
    end

    begin
      return load_list(@options.whitelist, :whitelist)
    rescue => e
      abort e
    end
  end # load_whitelist

  #
  # Returns <em>true</em> if the passed URL is referrer spam, <em>false</em>
  # otherwise.
  #
  def self.spam?(url)
    @cache.fetch(url) do |url|
      # Check the whitelist.
      unless @options.whitelist.nil?
        @whitelist[:regexps].each do |wl_regexp|
          return @cache[url] = false if url =~ wl_regexp
        end
      end

      # Check the blacklist.
      @blacklist[:regexps].each do |bl_regexp|
        return @cache[url] = true if url =~ bl_regexp
      end

      return @cache[url] = false
    end
  end

  # -- Main program -----------------------------------------------------------

  if __FILE__ == $0
    optparse = OptionParser.new do |optparse|
      optparse.summary_width  = 24
      optparse.summary_indent = '  '

      optparse.banner = "Usage: referrercop [-f | -i | -n | -s] [options] [<file> ...]\n" +
                        "       referrercop -u <url> [options]\n" +
                        "       referrercop -U [options]\n" +
                        "       referrercop {-h | -V}"

      optparse.separator ''
      optparse.separator 'Modes:'

      optparse.on('-f', '--filter',
        'Filter the specified files (or standard input if no',
        'files are specified), sending the results to',
        'standard output. This is the default mode.') do
        @options.mode = :filter
      end

      optparse.on('-i', '--in-place',
        'Filter the specified files in place, replacing each',
        'file with the filtered version. A backup of the',
        'original file will be created with a .bak extension.') do
        @options.mode = :inplace
      end

      optparse.on('-n', '--extract-ham',
        'Extract ham (nonspam) URLs from the input data and',
        'send them to standard output. Duplicates will be',
        'suppressed.') do
        @options.mode = :extract_ham
      end

      optparse.on('-s', '--extract-spam',
        'Extract spam URLs from the input data and send',
        'them to standard output. Duplicates will be',
        'suppressed.') do
        @options.mode = :extract_spam
      end

      optparse.on('-u', '--url <url>',
        'Test the specified URL.') do |url|
        @options.mode = :url
        @options.url  = url
      end

      optparse.on('-U', '--update',
        'Check for an updated version of the default',
        'blacklist and download it if available.') do
        @options.mode = :update
      end

      optparse.separator ''
      optparse.separator 'Options:'

      optparse.on('-b', '--blacklist <file>',
        'Blacklist to use instead of the default list.') do |filename|
        unless File.exist?(filename)
          raise("Blacklist not found - #{filename}")
        end

        @options.blacklist = filename
      end

      optparse.on('-c', '--config <file>',
        'Use the specified config file.') do |filename|
        @options.config_file = filename
      end

      optparse.on('-v', '--verbose',
        'Print verbose status and statistical info to stderr.') do
        $VERBOSE = true
      end

      optparse.on('-w', '--whitelist <file>',
        'Whitelist to use instead of the default list.') do |filename|
        unless File.exist?(filename)
          raise("Whitelist not found - #{filename}")
        end

        @options.whitelist = filename
      end

      optparse.separator ''
      optparse.separator 'Information:'

      optparse.on_tail('-h', '--help',
        'Display usage information (this message).') do
        puts optparse
        exit
      end

      optparse.on_tail('-V', '--version',
        'Display version information.') do
        puts "#{APP_NAME} v#{APP_VERSION} <http://referrercop.org/>"
        puts 'Copyright (c) 2006 Ryan Grove <ryan@wonko.com>.'
        puts
        puts "#{APP_NAME} comes with ABSOLUTELY NO WARRANTY."
        puts
        puts 'This program is open source software distributed under the terms of the'
        puts 'GNU General Public License. For details, see the LICENSE file contained in'
        puts 'the source distribution.'
        exit
      end
    end

    begin
      optparse.parse!(ARGV)
    rescue => e
      abort("Error: #{e}")
    end

    # Display header if in verbose mode.
    if $VERBOSE
      $stderr.puts "#{APP_NAME} v#{APP_VERSION} <http://referrercop.org/>"
      $stderr.puts 'Copyright (c) 2006 Ryan Grove <ryan@wonko.com>.'
      $stderr.puts
    end

    # Load config file.
    if @options.config_file.nil?
      CONFIG_PATHS.each do |path|
        filename = File.join(path, 'referrercop.conf')

        if File.exist?(filename)
          @options.config_file = filename
          break
        end
      end
    end

    ReferrerCopConfig::load_config(@options.config_file)

    # Load lists.
    @blacklist = load_blacklist(@options.blacklist)
    @whitelist = load_whitelist(@options.whitelist)

    # Determine the mode and perform the appropriate actions.
    @stats.start = Time.now.to_f

    case @options.mode
      when :filter
        if ARGV.length
          while filename = ARGV.shift
            $stderr.puts "Filtering #{filename}" if $VERBOSE

            File.open(filename, 'r') do |input|
              filter(input, $stdout)
            end
          end
        else
          filter($stdin, $stdout)
        end

      when :inplace
        abort('Error: No files specified.') unless ARGV.length

        while filename = ARGV.shift
          $stderr.puts "Filtering #{filename} in place" if $VERBOSE

          FileUtils.move(filename, filename + '.bak', :force => true)

          File.open(filename + '.bak', 'r') do |input|
            File.open(filename, 'w') do |output|
              filter(input, output)
            end
          end
        end

      when :extract_ham, :extract_spam
        extracted = Array.new

        if @options.mode == :extract_ham
          type = :ham
        else
          type = :spam
        end

        if ARGV.length
          while filename = ARGV.shift
            $stderr.puts "Extracting URLs from #{filename}" if $VERBOSE
            File.open(filename, 'r') {|input| extracted += extract(input, type) }
          end
        else
          extracted = extract($stdin, type)
        end

        $stdout.puts extracted.uniq.sort

      when :url
        if spam?(@options.url)
          puts 'Spam'
        else
          puts 'Ham'
        end

        exit

      when :update
        $stderr.puts "Checking for updated blacklist..." if $VERBOSE

        begin
          # Get the SHA1 checksum of the latest remote blacklist.
          remote_hash = Net::HTTP.get(URI.parse(
            ReferrerCopConfig::UPDATE_SHA1_URL))

          # Compare the remote hash to the local hash.
          if remote_hash.strip == @blacklist[:hash].strip
            $stderr.puts "No update necessary." if $VERBOSE
            exit
          end

        rescue => e
          abort 'Error: Unable to connect to update server.'
        end

        # Download the updated blacklist.
        $stderr.puts "Downloading new blacklist to #{@options.blacklist}" if $VERBOSE

        begin
          # Download the file.
          File.open(@options.blacklist + '.gz', 'w') do |file|
            file.write(Net::HTTP.get(URI.parse(
              ReferrerCopConfig::UPDATE_URL)))
          end

          # Unzip the file.
          File.open(@options.blacklist, 'w') do |file|
            Zlib::GzipReader.open(@options.blacklist + '.gz') do |gz|
              while data = gz.read(8192) do
                file.write(data)
              end
            end
          end

          # Delete the .gz file.
          File.delete(@options.blacklist + '.gz')

        rescue => e
          abort "Error: #{e}"
        end

        exit
    end

    @stats.end = Time.now.to_f

    # Display statistics if in verbose mode.
    if $VERBOSE && @stats.lines > 0
      time = @stats.end - @stats.start

      if time > 0
        speed = (@stats.lines / time).round
      else
        speed = 0
      end

      $stderr.puts
      $stderr.puts "Processed #{@stats.lines} lines in #{time}s " +
        "(#{speed} lines per second)"
      $stderr.puts "#{@stats.ham} ham, #{@stats.spam} spam, #{@stats.invalid} invalid"
    end
  end

end # module ReferrerCop