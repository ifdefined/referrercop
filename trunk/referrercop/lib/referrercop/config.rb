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
  
  module Config
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

  end

end
