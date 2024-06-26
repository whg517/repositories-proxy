
addEventListener('fetch', (event: FetchEvent) => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request: Request): Promise<Response> {
    let response: Response = await fetch(request);
    // Clone the response so we can modify the headers
    let newResponse: Response = new Response(response.body, response);
    // Set the Cache-Control header to cache the response for 3600 seconds
    newResponse.headers.set("Cache-Control", "max-age=3600");
    return newResponse;
}

// Docker镜像仓库主机地址
let hubHost: string = 'registry-1.docker.io';
// Docker认证服务器地址
const authUrl: string = 'https://auth.docker.io';

// 根据主机名选择对应的上游地址
function routeByHosts(host: string): [string, boolean] {
	// 定义路由表
	const routes: Record<string, string> = {
		// 生产环境
		"quay": "quay.io",
		"gcr": "gcr.io",
		"k8s-gcr": "k8s.gcr.io",
		"k8s": "registry.k8s.io",
		"ghcr": "ghcr.io",
		"cloudsmith": "docker.cloudsmith.io",
		"stackable": "docker.stackable.tech",

		// 测试环境
		"test": "registry-1.docker.io",
	};

	if (host in routes) return [routes[host], false];
	else return [hubHost, true];
}

/** @type {RequestInit} */
const PREFLIGHT_INIT: RequestInit = {
	// 预检请求配置
	headers: new Headers({
		'access-control-allow-origin': '*', // 允许所有来源
		'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS', // 允许的HTTP方法
		'access-control-max-age': '1728000', // 预检请求的缓存时间
	}),
}

/**
 * 构造响应
 * @param body 响应体
 * @param status 响应状态码
 * @param headers 响应头
 */
function makeRes(body: any, status: number = 200, headers: Record<string, string> = {}): Response {
	headers['access-control-allow-origin'] = '*' // 允许所有来源
	return new Response(body, { status, headers }) // 返回新构造的响应
}

/**
 * 构造新的URL对象
 * @param urlStr URL字符串
 */
function newUrl(urlStr: string): URL | null {
	try {
		return new URL(urlStr); // 尝试构造新的URL对象
	} catch (err) {
		return null; // 构造失败返回null
	}
}

async function nginx() {
	const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
	return text;
}

// 定义辅助函数
const getReqHeader = (request: Request, key: string): string | null => request.headers.get(key);
const isUUID = (str: string): boolean => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(str);


// 主函数
export default {
	async fetch(request: Request, env: any, ctx: any): Promise<Response> {
		let url = new URL(request.url);
		let workers_url = `https://${url.hostname}`;
		const pathname = url.pathname;
		const hostname = url.searchParams.get('hubhost') || url.hostname;
		const hostTop = hostname.split('.')[0];
		const [hub_host, fakePage] = routeByHosts(hostTop);
		console.log(`域名头部: ${hostTop}\n反代地址: ${hub_host}\n伪装首页: ${fakePage}`);
		const isUuid = isUUID(pathname.split('/')[1].split('/')[0]);

		const conditions = [
			isUuid,
			pathname.includes('/_'),
			pathname.includes('/r'),
			pathname.includes('/v2/user'),
			pathname.includes('/v2/orgs'),
			pathname.includes('/v2/_catalog'),
			pathname.includes('/v2/categories'),
			pathname.includes('/v2/feature-flags'),
			pathname.includes('search'),
			pathname.includes('source'),
			pathname === '/',
			pathname === '/favicon.ico',
			pathname === '/auth/profile',
		];

		if (conditions.some(condition => condition) && (fakePage === true || hostTop == 'docker')) {
			if (env.URL302) {
				return Response.redirect(env.URL302, 302);
			} else if (env.URL) {
				if (env.URL.toLowerCase() == 'nginx') {
					return new Response(await nginx(), {
						headers: {
							'Content-Type': 'text/html; charset=UTF-8',
						},
					});
				} else return fetch(new Request(env.URL, request));
			}

			const newUrl = new URL("https://registry.hub.docker.com" + pathname + url.search);
			const headers = new Headers(request.headers);
			headers.set('Host', 'registry.hub.docker.com');
			const newRequest = new Request(newUrl.toString(), {
				method: request.method,
				headers: headers,
				body: request.method !== 'GET' && request.method !== 'HEAD' ? await request.blob() : null,
				redirect: 'follow'
			});

			return fetch(newRequest);
		}

		if (!/%2F/.test(url.search) && /%3A/.test(url.toString())) {
			let modifiedUrl = url.toString().replace(/%3A(?=.*?&)/, '%3Alibrary%2F');
			url = new URL(modifiedUrl);
			console.log(`handle_url: ${url}`)
		}

		if (url.pathname.includes('/token')) {
		const tokenParameter: RequestInit = {
			headers: new Headers({
				'Host': 'auth.docker.io',
				'User-Agent': getReqHeader(request, "User-Agent")!,
				'Accept': getReqHeader(request, "Accept")!,
				'Accept-Language': getReqHeader(request, "Accept-Language")!,
				'Accept-Encoding': getReqHeader(request, "Accept-Encoding")!,
				'Connection': 'keep-alive',
			})
		};
		const tokenUrl = `${workers_url}${url.pathname}${url.search}`;
		return fetch(new Request(tokenUrl, tokenParameter));
		}

		if (/^\/v2\/[^/]+\/[^/]+\/[^/]+$/.test(url.pathname) && !/^\/v2\/library/.test(url.pathname)) {
			url.pathname = url.pathname.replace(/\/v2\//, '/v2/library/');
			console.log(`modified_url: ${url.pathname}`)
		}

		url.hostname = hub_host;
		let headers = new Headers({
			'Host': hub_host,
			'User-Agent': request.headers.get("User-Agent")!,
			'Accept': request.headers.get("Accept")!,
			'Accept-Language': request.headers.get("Accept-Language")!,
			'Accept-Encoding': request.headers.get("Accept-Encoding")!,
			'Connection': 'keep-alive',
		});

		if (request.headers.has("Authorization")) {
			headers.append("Authorization", request.headers.get("Authorization")!);
		}

		let parameter: RequestInit = {
			headers: headers,
		};

		let original_response = await fetch(new Request(url.toString(), parameter));
		let original_response_clone = original_response.clone();
		let original_text = await original_response_clone.text();
		let response_headers = original_response.headers;
		let new_response_headers = new Headers(response_headers);
		let status = original_response.status;

		if (new_response_headers.get("Www-Authenticate")) {
			let auth = new_response_headers.get("Www-Authenticate")!;
			let re = new RegExp(workers_url, 'g');
			new_response_headers.set("Www-Authenticate", auth.replace(re, workers_url));
		}

		if (new_response_headers.get("Location")) {
			return httpHandler(request, new_response_headers.get("Location")!);
		}

		return new Response(original_text, {
			status,
			headers: new_response_headers
		});
	}
};


/**
 * 处理HTTP请求
 * @param req 请求对象
 * @param pathname 请求路径
 */
function httpHandler(req: Request, pathname: string): Response | Promise<Response> {
	const reqHdrRaw = req.headers;

	// 预设的预检请求响应
	const PREFLIGHT_INIT: ResponseInit = {
		status: 204,
		headers: new Headers({
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
			"Access-Control-Allow-Headers": reqHdrRaw.get("access-control-request-headers") || "",
		}),
	};

	// 处理预检请求
	if (req.method === 'OPTIONS' && reqHdrRaw.has('access-control-request-headers')) {
		return new Response(null, PREFLIGHT_INIT);
	}

	let rawLen = '';

	const reqHdrNew = new Headers(reqHdrRaw);

	const refer = reqHdrNew.get('referer');

	let urlStr = pathname;

	const urlObj = new URL(urlStr);

	/** 请求初始化对象 */
	const reqInit: RequestInit = {
		method: req.method,
		headers: reqHdrNew,
		redirect: 'follow',
		body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : null,
	};
	return proxy(urlObj, reqInit, rawLen);
}

/**
 * 代理请求
 * @param urlObj URL对象
 * @param reqInit 请求初始化对象
 * @param rawLen 原始长度
 */
async function proxy(urlObj: URL, reqInit: RequestInit, rawLen: string): Promise<Response> {
	const res = await fetch(urlObj.href, reqInit);
	const resHdrOld = res.headers;
	const resHdrNew = new Headers(resHdrOld);

	// 验证长度
	if (rawLen) {
		const newLen = resHdrOld.get('content-length') || '';
		const badLen = (rawLen !== newLen);

		if (badLen) {
			return new Response(res.body, {
				status: 400,
				headers: {
					'--error': `bad len: ${newLen}, except: ${rawLen}`,
					'access-control-expose-headers': '--error',
				},
			});
		}
	}
	const status = res.status;
	resHdrNew.set('access-control-expose-headers', '*');
	resHdrNew.set('access-control-allow-origin', '*');
	resHdrNew.set('Cache-Control', 'max-age=1500');

	// 删除不必要的头
	resHdrNew.delete('content-security-policy');
	resHdrNew.delete('content-security-policy-report-only');
	resHdrNew.delete('clear-site-data');

	return new Response(res.body, {
		status,
		headers: resHdrNew,
	});
}