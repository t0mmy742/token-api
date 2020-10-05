# Token API

[![Build Status](https://travis-ci.com/t0mmy742/token-api.svg?branch=master)](https://travis-ci.com/t0mmy742/token-api)
[![Coverage Status](https://coveralls.io/repos/github/t0mmy742/token-api/badge.svg?branch=master)](https://coveralls.io/github/t0mmy742/token-api?branch=master)

`t0mmy742/token-api` is a token manager used for securing an API.
Username and password can be used to retrieve a new access token and a new refresh token.
When the access token expired, refresh token can be used to get another access token without using user's credentials.

This library mainly based on the `resource owner password credentials grant` and `refresh grant` of the `league/oauth2-server` implementation of OAuth 2.0.
However, `t0mmy742/token-api` does NOT aim to provide an OAuth 2.0 implementation.
It can only help you to create public API.

## Installation

```bash
$ composer require t0mmy742/token-api
```

## Usage

See [README.md](https://github.com/t0mmy742/token-api/blob/master/examples/README.md) file in `examples` directory.
