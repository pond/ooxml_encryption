# ============================================================================
# PREAMBLE
# ============================================================================

ENV['RACK_ENV'] = 'test'

# Get code coverage reports:
#
# https://github.com/colszowka/simplecov#getting-started
#
# "Load and launch SimpleCov at the very top of your test/test_helper.rb (or
#  spec_helper.rb [...])"
#
require 'simplecov'
SimpleCov.start()

require 'debug'
require 'ooxml_encryption'

# ============================================================================
# MAIN RSPEC CONFIGURATION
# ============================================================================

RSpec.configure do | config |
  config.disable_monkey_patching!

  config.color = true
  config.tty   = true
  config.order = :random

  Kernel.srand config.seed
end
