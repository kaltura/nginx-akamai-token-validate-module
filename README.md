# Akamai token validation module for Nginx

Validates Akamai v2 query string tokens

## Installation

Add `--add-module` when configuring nginx:

    ./configure --add-module=$PATH_TO_AKAMAI_TOKEN_VALIDATE

Requires OpenSSL.

## Configuration

#### akamai_token_validate
* **syntax**: `akamai_token_validate token`
* **default**: `off`
* **context**: `http`, `server`, `location`

Sets the value of the token that should be validated.
The parameter value can contain variables, e.g. $arg_token.

#### akamai_token_validate_key
* **syntax**: `akamai_token_validate_key key_hex`
* **default**: `empty`
* **context**: `http`, `server`, `location`

Sets the secret key

#### akamai_token_validate_uri_filename_prefix
* **syntax**: `akamai_token_validate_uri_filename_prefix prefix`
* **default**: `none`
* **context**: `http`, `server`, `location`

Defines a set of prefixes that will be matched against the URI file name, only URIs whose file name
starts with one of the defined prefixes will require a token

#### akamai_token_validate_strip_token
* **syntax**: `akamai_token_validate_strip_token param_name`
* **default**: `none`
* **context**: `http`, `server`, `location`

This setting can be used to strip query parameters, set it to the name of the parameter to strip.
The default behavior is not to strip any query parameters.
This setting is useful when the validated requests are proxied to some upstream server (using proxy_pass) - 
it can be used to remove the token from the upstream request

### Sample configuration
The following configuration requires a token parameter named `token`, either as a query string parameter or as a cookie:
```
http {

	server {

		if ($arg_token) {
			set $test_token $arg_token;
		}

		if ($cookie_token) {
			set $test_token $cookie_token;
		}

		location /protected/ {
			akamai_token_validate $test_token;
			akamai_token_validate_key 1234;
		}
	}
}
```
A protected URL may look something like:
`http://domain/protected/?token=st=1498386079~exp=1498386379~acl=/protected/*~hmac=3fea342b4b69149f8a34ff709913ad8676a3495172e4ac3f387b23554aa3a761`

Few more samples can be found here: https://github.com/kaltura/nginx-secure-token-module#sample-configurations

## Copyright & License

All code in this project is released under the [AGPLv3 license](http://www.gnu.org/licenses/agpl-3.0.html) unless a different license for a particular library is specified in the applicable library path. 

Copyright © Kaltura Inc. All rights reserved.
