require 'rubygems'

Gem::manage_gems

require 'rake/gempackagetask'
require 'rake/rdoctask'

spec = Gem::Specification.new do |s|
  s.name     = 'referrercop'
  s.version  = '2.0.0'
  s.author   = 'Ryan Grove'
  s.email    = 'ryan@wonko.com'
  s.homepage = 'http://wonko.com/software/referrercop/'
  s.platform = Gem::Platform::RUBY
  s.summary  = "Parses an Apache log file or AWStats data file and filters " +
               "out referrer spam."
  
  s.rubyforge_project = 'referrercop'

  s.files        = FileList['{bin,lib}/**/*', 'LICENSE', 'HISTORY'].exclude('rdoc').to_a
  s.executables  = ['referrercop']
  s.require_path = 'lib'
  s.autorequire  = 'referrercop'

  s.has_rdoc         = true
  s.extra_rdoc_files = ['README', 'LICENSE']
  s.rdoc_options << '--title' << 'ReferrerCop Documentation' <<
                    '--main' << 'README' <<
                    '--line-numbers'

  s.required_ruby_version = '>= 1.8.5'
end

Rake::GemPackageTask.new(spec) do |pkg|
  pkg.need_tar = true
end

Rake::RDocTask.new do |rd|
  rd.main     = 'README'
  rd.title    = 'Referrercop Documentation'
  rd.rdoc_dir = 'doc/html'
  rd.rdoc_files.include('README', 'bin/**/*', 'lib/**/*.rb')
end
