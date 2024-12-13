/**
 * 云函数入口
 *
 * 代理 oci 注册表请求。解决网络无法直达的问题。
 *
 * 例如默认的主域名是 example.com
 *
 * 当请求 docker.example.com 会将流量代理到 registry.hub.docker.com
 * 当请求 gcr.example.com 会将流量代理到 gcr.io
 *
 * 在开发模式下，会将 localhost 的请求流量代理到 registry.hub.docker.com。可以通过配置 docker 镜像加速地址来测试开发过程。
 */

import { ExecutionContext } from '@cloudflare/workers-types';
import { getProxyRule } from './config';
import { Env, AuthorizationConfig } from './types';

// CORS 相关常量配置
const CORS_HEADERS = {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, PUT, POST, DELETE, HEAD, OPTIONS',
    'access-control-allow-headers': '*',
    'access-control-max-age': '86400',
};

const HEADER_WWW_AUTHENTICATE = 'www-authenticate';
const HEADER_AUTHORIZATION = 'authorization';
const BEARER_PATTERN = /^Bearer\s+/;
const BASIC_PATTERN = /^Basic\s+/;

async function httpClient(request: Request, originalRequest: Request): Promise<Response> {
    console.log('Send Request to server:', { 'url': request.url, 'method': request.method }, 'headers:', Object.fromEntries(request.headers));
    const response = await fetch(request);
    console.log('Get Response from server:', { 'url': response.url, 'status': response.status });

    return await handleResponse(response, originalRequest);

}


/**
 * 处理预检请求
 */
async function handlePreflight(): Promise<Response> {
    return new Response(null, { headers: CORS_HEADERS });
}

/**
 * 处理请求前的逻辑
 */
async function handleRequest(request: Request, targetHost: string): Promise<Request> {
    const url = new URL(request.url);
    const targetUrl = new URL(`https://${targetHost}${url.pathname}${url.search}`);

    // 创建新的请求头
    const headers = new Headers(request.headers);
    headers.set('host', targetHost);

    console.log('Original request:', {
        'url': url.toString(),
        'headers': Object.fromEntries(headers),
    });

    return new Request(targetUrl.toString(), {
        method: request.method,
        headers: headers,
        body: request.bodyUsed ? null : request.body,
        redirect: 'follow',
    });
}

/**
 * 处理响应后的逻辑
 */
async function handleResponse(response: Response, originalRequest: Request): Promise<Response> {

    let responseHeaders = new Headers(response.headers);

    // 过滤响应头
    for (const [key, value] of response.headers.entries()) {
        if (!['set-cookie', 'strict-transport-security', 'transfer-encoding'].includes(key.toLowerCase())) {
            responseHeaders.set(key, value);
        }
    }

    // 处理 CORS
    responseHeaders.set('access-control-allow-origin', '*');
    if (originalRequest.method === 'OPTIONS') {
        responseHeaders.set('access-control-allow-methods', 'GET, PUT, POST, DELETE, HEAD, OPTIONS');
        responseHeaders.set('access-control-allow-headers', '*');
    }

    // 处理认证信息
    responseHeaders = postResponseAuthHeaders(responseHeaders, new URL(originalRequest.url));

    console.log('handled Response:', { 'url': response.url, 'headers': Object.fromEntries(responseHeaders), 'status': response.status });
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
    });
}


// 如果使用 docker login ，首次响应会有 www-authenticate 头，需要替换为当前代理地址
// 在下次请求时，会进入 /v2/auth 地址，获取 token
function postResponseAuthHeaders(headers: Headers, originalUrl: URL): Headers {
    const wwwAuthenticate = headers.get(HEADER_WWW_AUTHENTICATE);
    if (wwwAuthenticate) {
        const auth = wwwAuthenticate.replace(/realm="([^"]+)"/, `realm="${originalUrl.protocol}//${originalUrl.host}/v2/auth"`);
        headers.set(HEADER_WWW_AUTHENTICATE, auth);
    }
    return headers;
}

/**
 *  检查是否是认证用户
 *  example: Authorization: Basic foobarxxxzzz
 * @param authHeader    request.headers.get('authorization')
 * @param users        认证用户列表
 * @returns
 */
function checkAutnUser(authHeader: string, users: string[]): boolean {
    if (!authHeader) {
        return false;
    }
    const auth = authHeader.replace(BASIC_PATTERN, '');
    // decode base64 auth
    const authUser = atob(auth).split(':')[0];
    return users.includes(authUser);
}


/**
 *  example: www-authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
 * @param wwwAUth
 * @returns
 */
function decodeAuthorizationConfig(wwwAUth: string): AuthorizationConfig {
    const authConfig: AuthorizationConfig = {
        Realm: '',
        Service: ''
    }
    if (!wwwAUth) {
        return authConfig;
    }

    const auth = wwwAUth.replace(BEARER_PATTERN, '');

    const params = new Map<string, string>();
    auth.split(',').forEach(item => {
        const [key, value] = item.split('=').map(part => part.trim().replace(/^"|"$/g, ''));
        params.set(key, value);
    });

    authConfig.Realm = params.get('realm') || '';
    authConfig.Service = params.get('service') || '';

    return authConfig;
}

// 代理登录，处理 /v2/auth/ 请求
async function login(request: Request, targetHost: string): Promise<Response> {
    const headers = new Headers(request.headers);
    headers.set('host', targetHost);
    const registryUrl = new URL(`https://${targetHost}/v2/`);
    const proxyRequest = new Request(registryUrl.toString(), {
        method: request.method,
        headers: headers,
        body: request.bodyUsed ? null : request.body,
        redirect: 'follow',
    });

    // 直接向目标地址发送请求，判断登录状态
    // 如果未登录，可以直接获取registry的登录地址
    const proxyResponse = await fetch(proxyRequest);

    if (proxyResponse.status !== 401) {
        console.log('Already login:', { 'url': proxyResponse.url, 'status': proxyResponse.status });
        return proxyResponse;
    }
    const wwwAuth = proxyResponse.headers.get(HEADER_WWW_AUTHENTICATE);
    if (!wwwAuth) {
        console.log('Not found www-authenticate header:', { 'url': proxyResponse.url, 'status': proxyResponse.status });
        return proxyResponse;
    }

    const authConfig = decodeAuthorizationConfig(wwwAuth);
    if (!authConfig.Realm || !authConfig.Service) {
        console.log('Invalid www-authenticate header:', { 'url': proxyResponse.url, 'status': proxyResponse.status });
        return proxyResponse;
    }
    const targetAuthURL = new URL(authConfig.Realm);
    targetAuthURL.searchParams.set('service', authConfig.Service);
    const originalUrl = new URL(request.url);
    const scope = originalUrl.searchParams.get('scope');
    if (scope) {
        targetAuthURL.searchParams.set('scope', scope);
    }

    headers.set('host', targetAuthURL.host);
    console.log('Login request:', { 'url': targetAuthURL.toString(), 'headers': Object.fromEntries(headers) });
    const loginRequest = new Request(targetAuthURL.toString(), {
        method: 'GET',
        headers: headers,
        redirect: 'follow',
    });
    const loginResponse = await httpClient(loginRequest, request);

    return loginResponse;
}


/**
 * 主要的代理处理逻辑
 */
async function proxy(request: Request, targetHost: string): Promise<Response> {
    const url = new URL(request.url);

    // 处理预检请求
    if (request.method === 'OPTIONS') {
        return handlePreflight();
    }

    // 认证流程开启第二次请求进入认证地址，获取 token
    if (url.pathname.startsWith('/v2/auth')) {
        return login(request, targetHost);
    }

    const targetUrl = new URL(`https://${targetHost}${url.pathname}${url.search}`);
    const headers = new Headers(request.headers);
    headers.set('host', targetHost);

    const proxyRequest = new Request(targetUrl, {
        method: request.method,
        headers: headers,
        body: request.bodyUsed ? null : request.body,
        redirect: 'follow',
    })

    return await httpClient(proxyRequest, request);

}

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        try {
            const url = new URL(request.url);
            const proxyRule = getProxyRule(env);
            const rule = proxyRule[url.hostname];
            if (!rule) {
                console.log('Not found rule:', { 'url': request.url, 'hostname': url.hostname });
                return new Response('Not Found', { status: 404 });
            }
            console.log('Incoming request:', { 'url': request.url, 'rule': rule, 'method': request.method, 'headers': Object.fromEntries(request.headers) });
            const response = await proxy(request, rule);
            console.log('Outgoing response:', { 'url': response.url, 'headers': Object.fromEntries(response.headers), 'status': response.status });
            return response;
        } catch (error) {
            console.error('Error processing request:', error);
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};
