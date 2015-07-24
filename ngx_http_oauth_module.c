
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) nglua.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


typedef struct {
    ngx_http_upstream_conf_t   upstream;

    ngx_str_t                  db;
    ngx_str_t                  table;

    ngx_str_t                  appid;
    ngx_str_t                  secret;

    time_t                     expires_in;

    ngx_int_t                  (*create_request)(ngx_http_request_t *r);
    ngx_int_t                  (*process_header)(ngx_http_request_t *r);
} ngx_http_oauth_loc_conf_t;


typedef struct {
    ngx_uint_t                 state;
    ngx_uint_t                 parse_state;

    ngx_str_t                  access_token;
    ngx_str_t                  expires_in;
    ngx_str_t                  last_used_time;

	u_char					  *access_token_begin;
	u_char					  *access_token_end;
	u_char					  *expires_in_begin;
	u_char					  *expires_in_end;
	u_char					  *last_used_time_begin;
	u_char					  *last_used_time_end;
} ngx_http_oauth_ctx_t;


static ngx_int_t ngx_http_oauth_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_oauth_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_oauth_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_oauth_filter_init(void *data);
static ngx_int_t ngx_http_oauth_filter(void *data, ssize_t bytes);
static void ngx_http_oauth_abort_request(ngx_http_request_t *r);
static void ngx_http_oauth_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_oauth_create_request_token_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_oauth_create_check_token_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_oauth_process_request_token_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_oauth_process_check_token_header(ngx_http_request_t *r);

static ngx_int_t ngx_http_oauth_generate_data(ngx_http_request_t *r);

static void *ngx_http_oauth_create_loc_conf(ngx_conf_t *cf);

static void *ngx_http_oauth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_oauth_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char* ngx_http_oauth_request_token(ngx_conf_t *cf, ngx_command_t *cmd, 
    void *conf);
static char* ngx_http_oauth_check_token(ngx_conf_t *cf, ngx_command_t *cmd, 
    void *conf);
static char* ngx_http_oauth_pass(ngx_conf_t *cf, ngx_http_oauth_loc_conf_t *olcf);

static ngx_int_t ngx_http_oauth_parse(ngx_http_request_t *r, 
	ngx_http_oauth_ctx_t *ctx);


#define NGX_HTTP_OAUTH_OPEN_INDEX       "P\t1\ttest\toauth_access_token\tACCESS_TOKEN\taccess_token,expires_in,last_used_time"
#define NGX_HTTP_OAUTH_RESPONSE_OK      "{\"errcode\":\"0\",\"errmsg\":\"ok\"}"


static ngx_command_t  ngx_http_oauth_commands[] = {

    { ngx_string("oauth_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("oauth_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("oauth_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("oauth_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("oauth_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("oauth_db"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, db),
      NULL },

    { ngx_string("oauth_table"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, table),
      NULL },

    { ngx_string("oauth_appid"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, appid),
      NULL },

    { ngx_string("oauth_secret"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, secret),
      NULL },

    { ngx_string("oauth_expires_in"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, expires_in),
      NULL },

    { ngx_string("oauth_token"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_oauth_request_token,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oauth_check"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_oauth_check_token,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_oauth_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_oauth_create_loc_conf,        /* create location configuration */
    ngx_http_oauth_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_oauth_module = {
    NGX_MODULE_V1,
    &ngx_http_oauth_module_ctx,            /* module context */
    ngx_http_oauth_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_oauth_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_upstream_t            *u;
    ngx_http_oauth_ctx_t           *ctx;
    ngx_http_oauth_loc_conf_t      *olcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    ngx_str_set(&u->schema, "oauth://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_oauth_module;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    u->conf = &olcf->upstream;

    u->create_request = ngx_http_oauth_create_request;
    u->reinit_request = ngx_http_oauth_reinit_request;
    u->process_header = ngx_http_oauth_process_header;
    u->abort_request = ngx_http_oauth_abort_request;
    u->finalize_request = ngx_http_oauth_finalize_request;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oauth_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_oauth_module);

    u->input_filter_init = ngx_http_oauth_filter_init;
    u->input_filter = ngx_http_oauth_filter;
    u->input_filter_ctx = r;

    r->main->count++;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_oauth_create_request(ngx_http_request_t *r)
{
    size_t                          len;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_oauth_loc_conf_t      *olcf;

    len = sizeof(NGX_HTTP_OAUTH_OPEN_INDEX) - 1 + sizeof(CRLF) - 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    b->last = ngx_copy(b->last, (u_char *) NGX_HTTP_OAUTH_OPEN_INDEX,
                       sizeof(NGX_HTTP_OAUTH_OPEN_INDEX) - 1);

    *b->last++ = CR; *b->last++ = LF;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    return olcf->create_request(r);
}


static ngx_int_t
ngx_http_oauth_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_process_header(ngx_http_request_t *r)
{
    u_char                        *p;
    ngx_http_upstream_t           *u;
    ngx_http_oauth_ctx_t          *ctx;
    ngx_http_oauth_loc_conf_t     *olcf;

    u = r->upstream;

again:

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    u->buffer.pos = p;

    return NGX_AGAIN;

found:

    if (*u->buffer.pos != '0') {
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_module);

    if (ctx->state == 0) {
    	u->buffer.pos = p + 1;
        ctx->state = 1;
        goto again;
    }

	u->buffer.pos++;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    return olcf->process_header(r);
}


static ngx_int_t
ngx_http_oauth_filter_init(void *data)
{
    ngx_http_request_t  *r = data;

    ngx_http_upstream_t  *u;

    u = r->upstream;

    u->length = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_filter(void *data, ssize_t bytes)
{
    return NGX_OK;
}


static void
ngx_http_oauth_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http oauth request");
    return;
}


static void
ngx_http_oauth_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http oauth request");

    return;
}


static ngx_int_t
ngx_http_oauth_create_request_token_request(ngx_http_request_t *r)
{
    size_t                          len;
    ngx_int_t                       rc;
    ngx_int_t                       key;
    ngx_str_t                       var;
    ngx_http_variable_value_t      *vv;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_oauth_ctx_t           *ctx;
    ngx_http_oauth_loc_conf_t      *olcf;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_module);

    ngx_str_set(&var, "arg_appid");

    key = ngx_hash_key(var.data, var.len);

    vv = ngx_http_get_variable(r, &var, key);

    if (vv->not_found) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "request param appid not found");
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (ngx_strncmp(vv->data, olcf->appid.data, olcf->appid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "appid not match %*s: %V", vv->len, vv->data, &olcf->appid);
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_str_set(&var, "arg_secret");

    key = ngx_hash_key(var.data, var.len);

    vv = ngx_http_get_variable(r, &var, key);

    if (vv->not_found) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "request param secret not found");
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (ngx_strncmp(vv->data, olcf->secret.data, olcf->secret.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "secret not match %*s: %V", vv->len, vv->data, &olcf->secret);
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_oauth_generate_data(r);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    
    len = sizeof("1\t+\t3\t") - 1 + ctx->access_token.len + 1 + ctx->expires_in.len + 1 + 
                    ctx->last_used_time.len + sizeof(CRLF) - 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs->next = cl;

    b->last = ngx_copy(b->last, (u_char *) "1\t+\t3\t", sizeof("1\t+\t3\t") - 1);

    b->last = ngx_copy(b->last, ctx->access_token.data, ctx->access_token.len);

    *b->last++ = '\t';

    b->last = ngx_copy(b->last, ctx->expires_in.data, ctx->expires_in.len);

    *b->last++ = '\t';

    b->last = ngx_copy(b->last, ctx->last_used_time.data, ctx->last_used_time.len);

    *b->last++ = CR; *b->last++ = LF;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_create_check_token_request(ngx_http_request_t *r)
{
    size_t                          len;
    ngx_int_t                       key;
    ngx_str_t                       var;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_variable_value_t      *vv;

    ngx_str_set(&var, "arg_access_token"); 

    key = ngx_hash_key(var.data, var.len);

    vv = ngx_http_get_variable(r, &var, key);

    if (vv->not_found) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "request param access_token not found");
        return NGX_HTTP_NOT_FOUND;
    }

    len = sizeof("1\t=\t1\t") - 1 + vv->len - 1 + sizeof(CRLF) - 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs->next = cl;

    b->last = ngx_copy(b->last, (u_char *) "1\t=\t1\t", sizeof("1\t=\t1\t") - 1);
    b->last = ngx_copy(b->last, vv->data, vv->len);

    *b->last++ = CR; *b->last++ = LF;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_process_request_token_header(ngx_http_request_t *r)
{
    size_t                          len;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_upstream_t            *u;
    ngx_http_oauth_ctx_t           *ctx;

    u = r->upstream;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_module);

    len = sizeof("{\"access_token\":\"") - 1 + ctx->access_token.len + sizeof("\",\"expires_in\":") - 1 + ctx->expires_in.len + 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->flush = 1;
    b->memory = 1;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    b->last = ngx_copy(b->last, (u_char *) "{\"access_token\":\"", sizeof("{\"access_token\":\"") - 1);
    b->last = ngx_copy(b->last, ctx->access_token.data, ctx->access_token.len);
    b->last = ngx_copy(b->last, (u_char *) "\",\"expires_in\":", sizeof("\",\"expires_in\":") - 1);
    b->last = ngx_copy(b->last, ctx->expires_in.data, ctx->expires_in.len);
    *b->last++ = '}';

    u->out_bufs = cl; 

    r->headers_out.content_type_len = sizeof("text/html") - 1;
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";

    u->headers_in.status_n = 200;
    u->state->status = 200;

    u->headers_in.content_length_n = b->last - b->pos;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_process_check_token_header(ngx_http_request_t *r)
{
    size_t                          len;
	ngx_int_t						rc;
    ngx_buf_t                      *b;
    time_t                          time_expires_in;
    time_t                          time_last_used_time;
    ngx_str_t                       expires_in;
    ngx_str_t                       last_used_time;
    ngx_chain_t                    *cl;
    ngx_http_upstream_t            *u;
	ngx_http_oauth_ctx_t		   *ctx;

    u = r->upstream;

	ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_module);

	rc = ngx_http_oauth_parse(r, ctx);

	if (rc != NGX_OK) {
		return rc;
	}

    expires_in.data = ctx->expires_in_begin;
    expires_in.len = ctx->expires_in_end - ctx->expires_in_begin;

    last_used_time.data = ctx->last_used_time_begin;
    last_used_time.len = ctx->last_used_time_end - ctx->last_used_time_begin;

    time_expires_in = ngx_parse_time(&expires_in, 1);
    if (time_expires_in == (time_t) NGX_ERROR) {
        return NGX_ERROR;
    }

    time_last_used_time = ngx_parse_time(&last_used_time, 1);
    if (time_last_used_time == (time_t) NGX_ERROR) {
        return NGX_ERROR;
    }

    if (time_last_used_time + time_expires_in < ngx_time()) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "access token has expired {%T}", time_expires_in);
        return NGX_ERROR;
    }

    len = sizeof(NGX_HTTP_OAUTH_RESPONSE_OK) - 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->flush = 1;
    b->memory = 1;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    b->last = ngx_copy(b->last, (u_char *) NGX_HTTP_OAUTH_RESPONSE_OK,
                       sizeof(NGX_HTTP_OAUTH_RESPONSE_OK) - 1);

    u->out_bufs = cl; 

    r->headers_out.content_type_len = sizeof("application/json") - 1;
    r->headers_out.content_type.len = sizeof("application/json") - 1;
    r->headers_out.content_type.data = (u_char *) "application/json";

    u->headers_in.status_n = 200;
    u->state->status = 200;

    u->headers_in.content_length_n = sizeof(NGX_HTTP_OAUTH_RESPONSE_OK) - 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_generate_data(ngx_http_request_t *r)
{
    ngx_md5_t                       md5;
    u_char                          md5_buf[16];
    ngx_str_t                       token;
    ngx_http_oauth_ctx_t           *ctx;
    ngx_http_oauth_loc_conf_t      *olcf;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_module);

    token.data = ngx_pnalloc(r->pool, sizeof("18446744073709551616_") - 1
                               + NGX_TIME_T_LEN);

    if (token.data == NULL) {
        return NGX_ERROR;
    }

    token.len = ngx_sprintf(token.data, "%ul_%T", ngx_random(), ngx_time())
                  - token.data;

    ctx->access_token.data = ngx_palloc(r->pool, 32);
    if (ctx->access_token.data == NULL) {
        return NGX_ERROR;
    }

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, token.data, token.len);
    ngx_md5_final(md5_buf, &md5);

    ngx_hex_dump(ctx->access_token.data, md5_buf, sizeof(md5_buf));

    ctx->access_token.len = 32;

    ctx->expires_in.data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (ctx->expires_in.data == NULL) {
        return NGX_ERROR;
    }

    ctx->expires_in.len = ngx_sprintf(ctx->expires_in.data, "%T", olcf->expires_in)
                  - ctx->expires_in.data;

    ctx->last_used_time.data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);

    if (ctx->last_used_time.data == NULL) {
        return NGX_ERROR;
    }

    ctx->last_used_time.len = ngx_sprintf(ctx->last_used_time.data, "%T", ngx_time())
                  - ctx->last_used_time.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_parse(ngx_http_request_t *r, ngx_http_oauth_ctx_t *ctx)
{
    u_char  	   		   c, ch, *p;
	ngx_buf_t	  		  *b;
	ngx_http_upstream_t	  *u;

    enum {
        sw_start = 0,
        sw_before_num,
        sw_after_num,
        sw_before_column1,
        sw_column1,
        sw_before_column2,
        sw_column2,
        sw_before_column3,
        sw_column3,
        sw_almost_done
    } state;

	u = r->upstream;

	b = &u->buffer;

    state = ctx->parse_state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        case sw_start:

            if (ch == '\t') {
            	state = sw_before_num;
                break;
            }

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;

        case sw_before_num:

            c = (u_char) (ch | 0x20);
            if (c == '3') {
            	state = sw_after_num;
                break;
            }

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;

        case sw_after_num:

            if (ch == '\t') {
            	state = sw_before_column1;
                break;
            }

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;

        case sw_before_column1:
            ctx->access_token_begin = p;
            state = sw_column1;
            break;

        case sw_column1:

            switch (ch) {
            case '\t':
                ctx->access_token_end = p;
                state = sw_before_column2;
                break;
            default:
				break;
            }
            break;

        case sw_before_column2:
            ctx->expires_in_begin = p;
            state = sw_column2;
            break;

        case sw_column2:

            switch (ch) {
            case '\t':
                ctx->expires_in_end = p;
                state = sw_before_column3;
                break;
            default:
				break;
            }
            break;

        case sw_before_column3:
            ctx->last_used_time_begin = p;
            state = sw_column3;
            break;

        case sw_column3:

            switch (ch) {
            case CR:
				ctx->last_used_time_end = p;
                state = sw_almost_done;
                break;
            case LF:
				ctx->last_used_time_end = p;
                goto done;
            default:
                break;
            }
            break;

        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }
    }

    b->pos = p;
    ctx->parse_state = state;

    return NGX_HTTP_UPSTREAM_INVALID_HEADER;

done:

    b->pos = p + 1;

    ctx->parse_state = sw_start;

    return NGX_OK;
}


static void *
ngx_http_oauth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_oauth_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oauth_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->expires_in = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_oauth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_oauth_loc_conf_t *prev = parent;
    ngx_http_oauth_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    ngx_conf_merge_str_value(conf->db, prev->db, "");
    ngx_conf_merge_str_value(conf->table, prev->table, "");

    ngx_conf_merge_sec_value(conf->expires_in, prev->expires_in, 7200);

    return NGX_CONF_OK;
}


static char *
ngx_http_oauth_request_token(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oauth_loc_conf_t *olcf = conf;

    if (ngx_http_oauth_pass(cf, olcf) == NGX_CONF_ERROR) {
        return NGX_CONF_ERROR;
    }

    olcf->create_request = ngx_http_oauth_create_request_token_request;
    olcf->process_header = ngx_http_oauth_process_request_token_header;

    return NGX_CONF_OK;
}


static char *
ngx_http_oauth_check_token(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oauth_loc_conf_t *olcf = conf;

    if (ngx_http_oauth_pass(cf, olcf) == NGX_CONF_ERROR) {
        return NGX_CONF_ERROR;
    }

    olcf->create_request = ngx_http_oauth_create_check_token_request;
    olcf->process_header = ngx_http_oauth_process_check_token_header;

    return NGX_CONF_OK;
}


static char *
ngx_http_oauth_pass(ngx_conf_t *cf, ngx_http_oauth_loc_conf_t *olcf)
{
    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    if (olcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    olcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (olcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_oauth_handler;

    return NGX_CONF_OK;
}
