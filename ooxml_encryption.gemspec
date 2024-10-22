# frozen_string_literal: true

require_relative 'lib/ooxml_encryption/version'

Gem::Specification.new do | s |
  s.name    = 'ooxml_encryption'
  s.version = OoxmlEncryption::VERSION
  s.date    = OoxmlEncryption::DATE
  s.authors = ['RIPA Global', 'Andrew David Hodgkinson']
  s.email   = ['dev@ripaglobal.com']

  s.summary               = 'Encrypt or decrypt OOXML spreadsheets'
  s.description           = 'Encrypt or decrypt OOXML spreadsheets'
  s.homepage              = 'https://www.ripaglobal.com/'
  s.license               = 'MIT'
  s.required_ruby_version = '>= 2.7.0'

  s.metadata['homepage_uri'   ] = s.homepage
  s.metadata['source_code_uri'] = 'https://github.com/RIPAGlobal/ooxml_encryption/'
  s.metadata['bug_tracker_uri'] = 'https://github.com/RIPAGlobal/ooxml_encryption/issues/'
  s.metadata['changelog_uri'  ] = 'https://github.com/RIPAGlobal/ooxml_encryption/blob/master/CHANGELOG.md'

  s.files = Dir['lib/**/*', 'LICENSE', 'Rakefile', 'README.md']

  s.bindir        = 'exe'
  s.executables   = s.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  s.require_paths = ['lib']

  s.add_dependency 'simple_cfb', '~> 0.1'
  s.add_dependency 'openssl',    '~> 3.0'
  s.add_dependency 'nokogiri',   '~> 1.13'

  s.add_development_dependency 'simplecov-rcov', '~> 0.3'
  s.add_development_dependency 'rdoc',           '~> 6.7'
  s.add_development_dependency 'rspec-rails',    '~> 7.0'
  s.add_development_dependency 'debug',          '~> 1.9'
  s.add_development_dependency 'doggo',          '~> 1.4'
end
