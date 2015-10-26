Gem::Specification.new do |s|
	s.name = %q{fastpbkdf2}
	s.version = "0.1.1"

	s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
	s.authors = ["S-YOU"]
	s.description = %q{Ruby bindings for fastpbkdf2}
	s.summary = %q{Ruby bindings for fastpbkdf2}
	s.email = %q{S-YOU@users.noreply.github.com}
	s.license = %q{MIT}
	s.homepage = %q{https://github.com/S-YOU/ruby-fastpbkdf2}
	s.require_paths = ["lib"]

	s.extensions = ["ext/fastpbkdf2_native/extconf.rb"]
	s.files = [
		"Rakefile",
		"ext/fastpbkdf2_native/fastpbkdf2.c",
		"ext/fastpbkdf2_native/fastpbkdf2.h",
		"ext/fastpbkdf2_native/binding.c",
		"ext/fastpbkdf2_native/extconf.rb",
		"lib/fastpbkdf2.rb"
	]

	s.add_runtime_dependency("rake-compiler", "~> 0")
	s.add_runtime_dependency("rake", "~> 10")
end
