#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define TIME_CHECK_MARGIN (10)		// a margin around the token start/end time to compensate for clock differences

typedef struct {
	ngx_http_complex_value_t* token;
	ngx_str_t 	key;
	ngx_array_t* filename_prefixes;
	ngx_str_t	strip_token;
} ngx_http_akamai_token_validate_loc_conf_t;

enum {
	STATE_INITIAL,
	STATE_WAIT_EQUAL,
	STATE_WAIT_TILDE,
};

typedef struct {
	ngx_str_t st;
	ngx_str_t exp;
	ngx_str_t acl;
	ngx_str_t ip;
	
	ngx_str_t hmac;
	ngx_str_t signed_part;
} ngx_http_akamai_token_t;

typedef struct {
	ngx_str_t name;
	int offset;
} ngx_http_akamai_token_field_t;

static const ngx_http_akamai_token_field_t token_fields[] = {
	{ ngx_string("st"), offsetof(ngx_http_akamai_token_t, st) },
	{ ngx_string("exp"), offsetof(ngx_http_akamai_token_t, exp) },
	{ ngx_string("acl"), offsetof(ngx_http_akamai_token_t, acl) },
	{ ngx_string("ip"), offsetof(ngx_http_akamai_token_t, ip) },
	{ ngx_null_string, 0 }
};

static ngx_int_t ngx_http_akamai_token_validate_init(ngx_conf_t *cf);
static void *ngx_http_akamai_token_validate_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_akamai_token_validate_merge_loc_conf(ngx_conf_t *cf,
	void *parent, void *child);

static char *ngx_conf_set_hex_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_akamai_token_validate_commands[] = {
	{ ngx_string("akamai_token_validate"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_akamai_token_validate_loc_conf_t, token),
	NULL },
	  
	{ ngx_string("akamai_token_validate_key"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_hex_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_akamai_token_validate_loc_conf_t, key),
	NULL },
	  
	{ ngx_string("akamai_token_validate_uri_filename_prefix"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_array_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_akamai_token_validate_loc_conf_t, filename_prefixes),
	NULL },

	{ ngx_string("akamai_token_validate_strip_token"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_akamai_token_validate_loc_conf_t, strip_token),
	NULL },

	ngx_null_command
};


static ngx_http_module_t  ngx_http_akamai_token_validate_module_ctx = {
	NULL,								  				/* preconfiguration */
	ngx_http_akamai_token_validate_init,				/* postconfiguration */

	NULL,								  				/* create main configuration */
	NULL,								  				/* init main configuration */

	NULL,								  				/* create server configuration */
	NULL,								  				/* merge server configuration */

	ngx_http_akamai_token_validate_create_loc_conf,	 	/* create location configuration */
	ngx_http_akamai_token_validate_merge_loc_conf		/* merge location configuration */
};

ngx_module_t  ngx_http_akamai_token_validate_module = {
	NGX_MODULE_V1,
	&ngx_http_akamai_token_validate_module_ctx,		/* module context */
	ngx_http_akamai_token_validate_commands,		/* module directives */
	NGX_HTTP_MODULE,								/* module type */
	NULL,											/* init master */
	NULL,											/* init module */
	NULL,											/* init process */
	NULL,											/* init thread */
	NULL,											/* exit thread */
	NULL,											/* exit process */
	NULL,											/* exit master */
	NGX_MODULE_V1_PADDING
};

static int 
ngx_conf_get_hex_char_value(int ch)
{
	if (ch >= '0' && ch <= '9') 
	{
		return (ch - '0');
	}

	ch = (ch | 0x20);		// lower case

	if (ch >= 'a' && ch <= 'f') 
	{
		return (ch - 'a' + 10);
	}
	
	return -1;
}

static char *
ngx_conf_set_hex_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *field;
	ngx_str_t *value;
	u_char *p;
	size_t i;
	int digit1;
	int digit2;

	field = (ngx_str_t *) ((u_char*)conf + cmd->offset);

	if (field->data)
	{
		return "is duplicate";
	}

	value = cf->args->elts;

	if (value[1].len & 0x1)
	{
		return "length is odd";
	}
	
	field->data = ngx_palloc(cf->pool, value[1].len >> 1);
	if (field->data == NULL)
	{
		return "alloc failed";
	}
	p = field->data;
	
	for (i = 0; i < value[1].len; i += 2)
	{
		digit1 = ngx_conf_get_hex_char_value(value[1].data[i]);
		digit2 = ngx_conf_get_hex_char_value(value[1].data[i + 1]);
		if (digit1 < 0 || digit2 < 0)
		{
			return "contains non hex chars";
		}
		*p++ = (digit1 << 4) | digit2;
	}
	field->len = p - field->data;

	return NGX_CONF_OK;
}

static ngx_flag_t
ngx_http_akamai_token_validate_parse(ngx_str_t* token, ngx_http_akamai_token_t* parsed_token)
{
	const ngx_http_akamai_token_field_t* cur_field;
	ngx_str_t param_value = ngx_null_string;
	ngx_str_t param_name = ngx_null_string;
	u_char* token_end = token->data + token->len;
	u_char* cur_pos;
	int state = STATE_INITIAL;
	
	ngx_memzero(parsed_token, sizeof(*parsed_token));
	
	for (cur_pos = token->data; cur_pos < token_end; cur_pos++)
	{
		switch (state)
		{
		case STATE_INITIAL:
			param_name.data = cur_pos;
			state = STATE_WAIT_EQUAL;
			break;
			
		case STATE_WAIT_EQUAL:
			if (*cur_pos != '=')
			{
				break;
			}
			param_name.len = cur_pos - param_name.data;
			param_value.data = cur_pos + 1;
			state = STATE_WAIT_TILDE;
			break;
			
		case STATE_WAIT_TILDE:
			if (*cur_pos != '~')
			{
				break;
			}
			param_value.len = cur_pos - param_value.data;
			
			for (cur_field = token_fields; cur_field->name.len; cur_field++)
			{
				if (cur_field->name.len == param_name.len && 
					ngx_memcmp(cur_field->name.data, param_name.data, cur_field->name.len) == 0)
				{
					*(ngx_str_t*)((u_char*)parsed_token + cur_field->offset) = param_value;
					break;
				}
			}
			
			state = STATE_INITIAL;
			break;
		}
	}
	
	// last parameter must be hmac
	if (state != STATE_WAIT_TILDE ||
		param_name.len != sizeof("hmac") - 1 ||
		ngx_memcmp(param_name.data, "hmac", sizeof("hmac") - 1) != 0)
	{
		return 0;
	}
	
	param_value.len = cur_pos - param_value.data;
	parsed_token->hmac = param_value;
	
	parsed_token->signed_part.data = token->data;
	if (param_name.data - 1 > token->data)
	{
		parsed_token->signed_part.len = param_name.data - 1 - token->data;
	}
	else
	{
		parsed_token->signed_part.len = 0;
	}
	
	return 1;
}

static ngx_flag_t
ngx_http_akamai_token_validate(ngx_http_request_t *r, ngx_str_t* token, ngx_str_t* key)
{
	ngx_http_akamai_token_t parsed_token;
	unsigned hash_len;
	u_char hash[EVP_MAX_MD_SIZE];
	u_char hash_hex[EVP_MAX_MD_SIZE * 2];
	ngx_str_t* addr_text;
	size_t hash_hex_len;
	ngx_int_t value;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	HMAC_CTX hmac_buf;
#endif
	HMAC_CTX* hmac;

	if (!ngx_http_akamai_token_validate_parse(token, &parsed_token))
	{
		return 0;
	}
	
	// validate the signature
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	hmac = HMAC_CTX_new();
	if (hmac == NULL)
	{
		return 0;
	}
#else
	hmac = &hmac_buf;
	HMAC_CTX_init(hmac);
#endif
	HMAC_Init_ex(hmac, key->data, key->len, EVP_sha256(), NULL);
	HMAC_Update(hmac, parsed_token.signed_part.data, parsed_token.signed_part.len);
	HMAC_Final(hmac, hash, &hash_len);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	HMAC_CTX_free(hmac);
#else
	HMAC_CTX_cleanup(hmac);
#endif
	hash_hex_len = ngx_hex_dump(hash_hex, hash, hash_len) - hash_hex;
	
	if (hash_hex_len != parsed_token.hmac.len ||
		ngx_memcmp(hash_hex, parsed_token.hmac.data, hash_hex_len) != 0)
	{
		return 0;
	}
	
	// validate the time
	if (parsed_token.st.len != 0)
	{
		value = ngx_atoi(parsed_token.st.data, parsed_token.st.len);
		if (value < 0) 
		{
			return 0;
		}
		
		if (value > ngx_time() + TIME_CHECK_MARGIN)
		{
			return 0;
		}
	}
	
	if (parsed_token.exp.len != 0)
	{
		value = ngx_atoi(parsed_token.exp.data, parsed_token.exp.len);
		if (value < 0) 
		{
			return 0;
		}
		
		if (value + TIME_CHECK_MARGIN < ngx_time())
		{
			return 0;
		}
	}

	// validate the acl
	if (parsed_token.acl.len != 0)
	{
		if (parsed_token.acl.data[parsed_token.acl.len - 1] == '*')
		{
			parsed_token.acl.len--;
			if (r->uri.len < parsed_token.acl.len || 
				ngx_memcmp(r->uri.data, parsed_token.acl.data, parsed_token.acl.len) != 0)
			{
				return 0;
			}
		}
		else
		{
			if (r->uri.len != parsed_token.acl.len || 
				ngx_memcmp(r->uri.data, parsed_token.acl.data, parsed_token.acl.len) != 0)
			{
				return 0;
			}
		}
	}
	
	// validate the ip
	if (parsed_token.ip.len != 0)
	{
		addr_text = &r->connection->addr_text;
		if (parsed_token.ip.len != addr_text->len ||
			ngx_memcmp(parsed_token.ip.data, addr_text->data, parsed_token.ip.len) != 0)
		{
			return 0;
		}
	}

	return 1;
}

static ngx_int_t
ngx_http_akamai_token_validate_strip_arg(ngx_http_request_t *r, ngx_str_t* arg_name, ngx_str_t* arg_value)
{
	u_char* arg_start = arg_value->data - arg_name->len - 1;	// 1 = the equal sign
	u_char* arg_end = arg_value->data + arg_value->len;
	u_char* uri_end = r->unparsed_uri.data + r->unparsed_uri.len;
	u_char* new_uri;
	u_char* p;

	// Note: this code assumes that the arg returned from ngx_http_arg points to a substring of 
	//	of r->unparsed_uri and r->args, that is always the case according to nginx code
	if (arg_start < r->unparsed_uri.data || arg_end > uri_end || 
		arg_start < r->args.data || arg_end > r->args.data + r->args.len)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_akamai_token_validate_module: unexpected, token is not within unparsed_uri / args");
		return NGX_ERROR;
	}

	new_uri = ngx_palloc(r->pool, r->unparsed_uri.len + 1);
	if (new_uri == NULL)
	{
		return NGX_ERROR;
	}

	p = ngx_copy(new_uri, r->unparsed_uri.data, arg_start - r->unparsed_uri.data);
	if (arg_end + 1 < uri_end)
	{
		p = ngx_copy(p, arg_end + 1, uri_end - arg_end - 1);
	}

	if (p[-1] == '?' || p[-1] == '&')
	{
		p--;
	}

	*p = '\0';

	r->args.data = new_uri + (r->args.data - r->unparsed_uri.data);
	if (r->args.data < p)
	{
		r->args.len = p - r->args.data;
	}
	else
	{
		r->args.len = 0;
	}

	r->unparsed_uri.data = new_uri;
	r->unparsed_uri.len = p - new_uri;

	return NGX_OK;
}

static void *
ngx_http_secure_token_validate_memrchr(const u_char *s, int c, size_t n)
{
	const u_char *cp;

	for (cp = s + n; cp > s;)
	{
		if (*(--cp) == (u_char)c)
			return (void*)cp;
	}
	return NULL;
}

static ngx_int_t
ngx_http_akamai_token_validate_handler(ngx_http_request_t *r)
{
	ngx_http_akamai_token_validate_loc_conf_t  *conf;
	ngx_flag_t prefix_matched;
	ngx_str_t uri_filename;
	ngx_str_t token;
	ngx_str_t* cur_prefix;
	ngx_uint_t i;
	u_char* last_slash_pos;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_akamai_token_validate_module);

	if (conf->token == NULL) 
	{
		return NGX_OK;
	}
	
	if (conf->filename_prefixes != NULL)
	{
		last_slash_pos = ngx_http_secure_token_validate_memrchr(r->uri.data, '/', r->uri.len);
		if (last_slash_pos == NULL) 
		{
			return NGX_HTTP_FORBIDDEN;
		}
	
		uri_filename.data = last_slash_pos + 1;
		uri_filename.len = r->uri.data + r->uri.len - uri_filename.data;

		prefix_matched = 0;
		for (i = 0; i < conf->filename_prefixes->nelts; i++)
		{
			cur_prefix = &((ngx_str_t*)conf->filename_prefixes->elts)[i];
			if (uri_filename.len >= cur_prefix->len &&
				ngx_memcmp(uri_filename.data, cur_prefix->data, cur_prefix->len) == 0)
			{
				prefix_matched = 1;
				break;
			}
		}

		if (!prefix_matched)
		{
			return NGX_OK;
		}
	}

	if (ngx_http_complex_value(r, conf->token, &token) != NGX_OK)
	{
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_http_akamai_token_validate(r, &token, &conf->key))
	{
		if (conf->strip_token.len != 0)
		{
			if (ngx_http_arg(r, conf->strip_token.data, conf->strip_token.len, &token) != NGX_OK)
			{
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			if (ngx_http_akamai_token_validate_strip_arg(r, &conf->strip_token, &token) != NGX_OK)
			{
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
		}

		return NGX_OK;
	}
	else
	{
		return NGX_HTTP_FORBIDDEN;
	}
}

static void *
ngx_http_akamai_token_validate_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_akamai_token_validate_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_akamai_token_validate_loc_conf_t));
	if (conf == NULL)
	{
		return NGX_CONF_ERROR;
	}

	conf->filename_prefixes = NGX_CONF_UNSET_PTR;
	return conf;
}


static char *
ngx_http_akamai_token_validate_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_akamai_token_validate_loc_conf_t  *prev = parent;
	ngx_http_akamai_token_validate_loc_conf_t  *conf = child;

	if (conf->token == NULL)
	{
		conf->token = prev->token;
	}
	ngx_conf_merge_str_value(conf->key, prev->key, "");
	ngx_conf_merge_ptr_value(conf->filename_prefixes, prev->filename_prefixes, NULL);
	ngx_conf_merge_str_value(conf->strip_token, prev->strip_token, "");
	return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_akamai_token_validate_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt		*h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL)
	{
		return NGX_ERROR;
	}

	*h = ngx_http_akamai_token_validate_handler;

	return NGX_OK;
}
