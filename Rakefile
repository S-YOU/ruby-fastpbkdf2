require 'rake/extensiontask'

spec = Gem::Specification.load('.gemspec')
Rake::ExtensionTask.new('fastpbkdf2_native', spec)

require 'rake/testtask'
Rake::TestTask.new do |t|
  t.libs << "test"
  t.test_files = FileList['test/ruby/test*.rb']
  t.verbose = true
end

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new(:spec)

task :default => :spec
