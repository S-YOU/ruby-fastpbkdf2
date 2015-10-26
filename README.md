##fastpbkdf2 [![Build Status](https://travis-ci.org/S-YOU/ruby-fastpbkdf2.svg?branch=master)](https://travis-ci.org/S-YOU/ruby-fastpbkdf2)

Ruby binding of https://github.com/ctz/fastpbkdf2 - CC0 License

### Install
```bash
gem install fastpbkdf2
```

```ruby
require('fastpbkdf2')

result = Fastpbkdf2::sha1("password", "salt", 1, 20)
```

### Interface
```ruby
Fastpbkdf2::sha1(password, salt, iterations, keylen);
Fastpbkdf2::sha256(password, salt, iterations, keylen);
Fastpbkdf2::sha512(password, salt, iterations, keylen);
```

###Manual Build
- clone this repo and use `bundle install; rake compile`
- `rake` to run tests

### License
MIT
