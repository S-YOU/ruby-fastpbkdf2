require './spec/helper'

describe 'unit tests for fastpbkdf2' do
	context "tests for sha1 (6 tests):" do
		context "should match correct strings" do
			result = Fastpbkdf2::sha1("password", "salt", 1, 20).unpack("H*")[0]
			expected = "\x0c\x60\xc8\x0f\x96\x1f\x0eq\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha1("password", "salt", 2, 20).unpack("H*")[0]
			expected = "\xeal\x01M\xc7\x2do\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89W".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha1("password", "salt", 4096, 20).unpack("H*")[0]
			expected = "K\x00y\x01\xb7\x65H\x9a\xbe\xadI\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha1("password", "salt", 16777216, 20).unpack("H*")[0]
			expected = "\xee\xfe\x3d\x61\xcdM\xa4\xe4\xe9\x94\x5b\x3dk\xa2\x15\x8c\x26\x34\xe9\x84".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha1("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25).unpack("H*")[0]
			expected = "\x3d\x2e\xecO\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4J\x8b\x29\x1a\x96L\xf2\xf0p\x38".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha1("pass\x00word", "sa\x00lt", 4096, 16).unpack("H*")[0]
			expected = "V\xfaj\xa7UH\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		end

	context "tests for sha256 (9 tests):" do
		context "should match correct strings" do
			result = Fastpbkdf2::sha256("passwd", "salt", 1, 64).unpack("H*")[0]
			expected = "U\xac\x04nV\xe3\x08\x9f\xec\x16\x91\xc2\x25\x44\xb6\x05\xf9\x41\x85\x21m\xde\x04\x65\xe6\x8b\x9dW\xc2\x0d\xac\xbcI\xca\x9c\xcc\xf1y\xb6\x45\x99\x16\x64\xb3\x9dw\xef\x31\x7cq\xb8\x45\xb1\xe3\x0b\xd5\x09\x11\x20\x41\xd3\xa1\x97\x83".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha256("Password", "NaCl", 80000, 64).unpack("H*")[0]
			expected = "M\xdc\xd8\xf6\x0b\x98\xbe\x21\x83\x0c\xee\x5e\xf2\x27\x01\xf9\x64\x1a\x44\x18\xd0L\x04\x14\xae\xff\x08\x87k\x34\xabV\xa1\xd4\x25\xa1\x22X\x33T\x9a\xdb\x84\x1bQ\xc9\xb3\x17j\x27\x2b\xde\xbb\xa1\xd0xG\x8f\x62\xb3\x97\xf3\x3c\x8d".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha256("password", "salt", 1, 32).unpack("H*")[0]
			expected = "\x12\x0f\xb6\xcf\xfc\xf8\xb3\x2c\x43\xe7\x22RV\xc4\xf8\x37\xa8\x65H\xc9\x2c\xcc\x35H\x08\x05\x98\x7c\xb7\x0b\xe1\x7b".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha256("password", "salt", 2, 32).unpack("H*")[0]
			expected = "\xaeM\x0c\x95\xafkF\xd3\x2d\x0a\xdf\xf9\x28\xf0m\xd0\x2a\x30\x3f\x8e\xf3\xc2Q\xdf\xd6\xe2\xd8Z\x95GLC".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha256("password", "salt", 4096, 32).unpack("H*")[0]
			expected = "\xc5\xe4x\xd5\x92\x88\xc8\x41\xaaS\x0d\xb6\x84\x5cL\x8d\x96\x28\x93\xa0\x01\xceN\x11\xa4\x96\x38s\xaa\x98\x13J".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha256("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40).unpack("H*")[0]
			expected = "\x34\x8c\x89\xdb\xcb\xd3\x2b\x2f\x32\xd8\x14\xb8\x11n\x84\xcf\x2b\x17\x34\x7e\xbc\x18\x00\x18\x1cN\x2a\x1f\xb8\xddS\xe1\xc6\x35Q\x8c\x7d\xacG\xe9".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha256("", "salt", 1024, 32).unpack("H*")[0]
			expected = "\x9e\x83\xf2y\xc0\x40\xf2\xa1\x1a\xa4\xa0\x2b\x24\xc4\x18\xf2\xd3\xcb\x39V\x0c\x96\x27\xfaOG\xe3\xbc\xc2\x89\x7c\x3d".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha256("password", "", 1024, 32).unpack("H*")[0]
			expected = "\xeaX\x08\x41\x1e\xb0\xc7\xe8\x30\xde\xabU\x09l\xeeX\x27\x61\xe2\x2a\x9b\xc0\x34\xe3\xec\xe9\x25\x22\x5b\x07\xbf\x46".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha256("pass\x00word", "sa\x00lt", 4096, 16).unpack("H*")[0]
			expected = "\x89\xb6\x9d\x05\x16\xf8\x29\x89\x3cib\x26\x65\x0a\x86\x87".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		end

	context "tests for sha512 (4 tests):" do
		context "should match correct strings" do
			result = Fastpbkdf2::sha512("password", "salt", 1, 32).unpack("H*")[0]
			expected = "\x86\x7fp\xcf\x1a\xde\x02\xcf\xf3u\x25\x99\xa3\xa5\x3d\xc4\xaf\x34\xc7\xa6i\x81Z\xe5\xd5\x13UN\x1c\x8c\xf2R".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha512("password", "salt", 2, 32).unpack("H*")[0]
			expected = "\xe1\xd9\xc1j\xa6\x81p\x8a\x45\xf5\xc7\xc4\xe2\x15\xce\xb6n\x01\x1a\x2e\x9f\x00\x40q\x3f\x18\xae\xfd\xb8\x66\xd5\x3c".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha512("password", "salt", 4096, 32).unpack("H*")[0]
			expected = "\xd1\x97\xb1\xb3\x3d\xb0\x14\x3e\x01\x8b\x12\xf3\xd1\xd1G\x9el\xde\xbd\xcc\x97\xc5\xc0\xf8\x7fi\x02\xe0r\xf4W\xb5".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		context "should match correct strings" do
			result = Fastpbkdf2::sha512("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 1, 72).unpack("H*")[0]
			expected = "n\x23\xf2v\x38\x08K\x0f\x7e\xa1sN\x0d\x98\x41\xf5\x5d\xd2\x9e\xa6\x0a\x83\x44\x66\xf3\x39k\xac\x80\x1f\xac\x1e\xeb\x63\x80\x2f\x03\xa0\xb4\xac\xd7\x60\x3e\x36\x99\xc8\xb7\x44\x37\xbe\x83\xff\x01\xad\x7fU\xda\xc1\xef\x60\xf4\xd5\x64\x80\xc3\x5e\xe6\x8f\xd5\x2ci\x36".unpack("H*")[0]
			it "should be same" do
				print "\n#{result != expected ? 'ERR' : 'OK'} #{result} #{expected}"
				expect(result).to eql(expected)
			end
		end
		end

end
