require 'rake'
require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'rdoc/task'
require 'sdoc'

RSpec::Core::RakeTask.new(:default) do | t |
end

Rake::RDocTask.new do | rd |
  rd.rdoc_files.include('README.md', 'lib/**/*.rb')

  rd.title     = 'OOXML Encryption'
  rd.main      = 'README.md'
  rd.rdoc_dir  = 'docs/rdoc'
  rd.generator = 'sdoc'
end
