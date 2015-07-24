
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) nglua.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t                 uri;
} ngx_http_oauth_request_conf_t;


typedef struct {
    ngx_uint_t                done;
    ngx_uint_t                status;
    ngx_http_request_t       *subrequest;
} ngx_http_oauth_request_ctx_t;


static ngx_int_t ngx_http_oauth_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_oauth_request_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static void *ngx_http_oauth_request_create_conf(ngx_conf_t *cf);
static char *ngx_http_oauth_request_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_oauth_request_init(ngx_conf_t *cf);
static char *ngx_http_oauth_request(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_oauth_request_commands[] = {

    { ngx_string("oauth_request"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_oauth_request,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_oauth_request_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_oauth_request_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_oauth_request_create_conf,    /* create location configuration */
    ngx_http_oauth_request_merge_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_oauth_request_module = {
    NGX_MODULE_V1,
    &ngx_http_oauth_request_module_ctx,    /* module context */
    ngx_http_oauth_request_commands,       /* module directives */
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
ngx_http_oauth_request_handler(ngx_http_request_t *r)
{
	u_char						  *p;
	ngx_int_t                      key;
	ngx_str_t                      var;
	ngx_str_t					  *args;
    ngx_http_request_t            *sr;
	ngx_http_variable_value_t     *vv;
    ngx_http_post_subrequest_t    *ps;
    ngx_http_oauth_request_ctx_t  *ctx;
    ngx_http_oauth_request_conf_t *orcf;

    orcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_request_module);

    if (orcf->uri.len == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth request handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_request_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        if (ctx->status == NGX_HTTP_OK) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth request unexpected status: %d", ctx->status);

        return NGX_HTTP_NOT_ALLOWED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oauth_request_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_oauth_request_done;
    ps->data = ctx;

    ngx_str_set(&var, "arg_access_token");

    key = ngx_hash_key(var.data, var.len);

    vv = ngx_http_get_variable(r, &var, key);

    if (vv->not_found) {
        return NGX_HTTP_NOT_ALLOWED;
    }

	args = ngx_palloc(r->pool, sizeof(ngx_str_t));
	if (args == NULL) {
		return NGX_ERROR;
	}

	args->len = sizeof("access_token=") - 1 + vv->len;

	args->data = ngx_palloc(r->pool, args->len);
	if (args->data == NULL) {
		return NGX_ERROR;
	}

	p = ngx_copy(args->data, (u_char *) "access_token=", sizeof("access_token=") - 1);
	p = ngx_copy(p, vv->data, vv->len);

    if (ngx_http_subrequest(r, &orcf->uri, args, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }

    sr->header_only = 1;

    ctx->subrequest = sr;

    ngx_http_set_ctx(r, ctx, ngx_http_oauth_request_module);

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_oauth_request_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_oauth_request_ctx_t   *ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request done s:%d", r->headers_out.status);

    ctx->done = 1;
    ctx->status = r->headers_out.status;

    return rc;
}


static void *
ngx_http_oauth_request_create_conf(ngx_conf_t *cf)
{
    ngx_http_oauth_request_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oauth_request_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->uri = { 0, NULL };
     */

    return conf;
}


static char *
ngx_http_oauth_request_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_oauth_request_conf_t *prev = parent;
    ngx_http_oauth_request_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->uri, prev->uri, "");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_oauth_request_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_oauth_request_handler;

    return NGX_OK;
}


static char *
ngx_http_oauth_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oauth_request_conf_t *orcf = conf;

    ngx_str_t        *value;

    if (orcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    orcf->uri = value[1];

    return NGX_CONF_OK;
}
