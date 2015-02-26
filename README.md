# Akamai token validation module for Nginx

Validates Akamai v2 query string tokens

## Installation

Add `--add-module` when configuring nginx:

    ./configure --add-module=$PATH_TO_AKAMAI_TOKEN_VALIDATE

Requires OpenSSL.

## Configuration

#### akamai_token_validate
* **syntax**: `akamai_token_validate on/off`
* **default**: `off`
* **context**: `http`, `server`, `location`

Enables / disables the module

#### akamai_token_validate_key
* **syntax**: `akamai_token_validate_key key_hex`
* **default**: `empty`
* **context**: `http`, `server`, `location`

Sets the secret key

#### akamai_token_validate_param_name
* **syntax**: `akamai_token_validate_param_name name`
* **default**: `__hdnea__`
* **context**: `http`, `server`, `location`

Sets the token query string parameter name

#### akamai_token_validate_uri_filename_prefix
* **syntax**: `akamai_token_validate_uri_filename_prefix prefix`
* **default**: `none`
* **context**: `http`, `server`, `location`

Defines a set of prefixes that will be matched against the URI file name, only URIs whose file name
starts with one of the defined prefixes will require a token

## Copyright & License

All code in this project is released under the [AGPLv3 license](http://www.gnu.org/licenses/agpl-3.0.html) unless a different license for a particular library is specified in the applicable library path. 

Copyright © Kaltura Inc. All rights reserved.
