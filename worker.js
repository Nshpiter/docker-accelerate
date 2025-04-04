// _worker.js
// --- Authentication Settings ---
const AUTH_COOKIE_NAME = 'docker_proxy_auth_token'; // 身份验证 cookie 的名称
// --- Original Configuration ---
let hub_host = 'registry-1.docker.io';
const auth_url = 'https://auth.docker.io';
let workers_url = ''; // 将动态设置
let 屏蔽爬虫UA = ['netcraft'];

// --- Helper Functions (Authentication) ---
/**
 * 生成 HTML 登录页面。
 * @param {string} [errorMessage] - 可选的错误信息。
 * @returns {Response} - 登录页面的 HTML 响应。
 */
function generateLoginPage(errorMessage = '') {
    const errorHtml = errorMessage ? `<p class="error-message">${errorMessage}</p>` : '';
    const html = `
 <!DOCTYPE html>
 <html>
 <head>
     <title>需要登录</title>
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
     <meta charset="UTF-8">
     <style>
         body {
             font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
             display: flex;
             justify-content: center;
             align-items: center;
             min-height: 100vh;
             background-image: url('https://pic.npiter.com/file/1743776724959_20250308_141126_4.jpg'); /* 背景图片 */
             background-size: cover; /* 覆盖整个区域 */
             background-position: center; /* 居中显示 */
             background-repeat: no-repeat; /* 不重复 */
             background-attachment: fixed; /* 固定背景 */
             margin: 0;
         }
         .login-container {
             background-color: rgba(255, 255, 255, 0.75); /* 75% 不透明度 */
             padding: 30px 40px;
             border-radius: 12px; /* 圆角稍大 */
             box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15); /* 阴影更明显 */
             text-align: center;
             max-width: 380px; /* 稍微加宽 */
             width: 90%;
             backdrop-filter: blur(5px); /* 毛玻璃效果 */
             -webkit-backdrop-filter: blur(5px); /* 兼容 Safari */
             border: 1px solid rgba(255, 255, 255, 0.2); /* 邊框也更透明 */
         }
         h2 {
             color: #333;
             margin-bottom: 20px;
             font-weight: 600; /* 标题加粗 */
         }
         p {
             color: #444; /* 段落颜色加深 */
             margin-bottom: 25px;
         }
         form {
             display: flex;
             flex-direction: column;
         }
         label {
             text-align: left;
             margin-bottom: 8px; /* 标签和输入框距离 */
             color: #444; /* 标签颜色加深 */
             font-weight: bold;
             font-size: 14px; /* 标签字体稍小 */
         }
         input[type="text"],
         input[type="password"] {
             padding: 12px 15px; /* 内边距调整 */
             margin-bottom: 18px; /* 输入框间距 */
             border: 1px solid #ccc;
             border-radius: 6px; /* 输入框圆角 */
             font-size: 16px;
             box-sizing: border-box; /* 防止 padding 影响宽度 */
             background-color: rgba(255, 255, 255, 0.8); /* 输入框稍微透明 */
         }
         input:focus {
             outline: none; /* 移除默认 focus 轮廓 */
             border-color: #007bff; /* focus 时边框变蓝 */
             box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25); /* 添加 focus 光晕 */
         }
         button {
             padding: 12px;
             background-color: #007bff;
             color: white;
             border: none;
             border-radius: 6px; /* 按钮圆角 */
             cursor: pointer;
             font-size: 16px;
             font-weight: 600; /* 按钮文字加粗 */
             transition: background-color 0.3s ease, box-shadow 0.3s ease; /* 添加阴影过渡 */
             margin-top: 10px; /* 按钮与上方元素间距 */
         }
         button:hover {
             background-color: #0056b3;
             box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); /* 悬停时加深阴影 */
         }
         .error-message {
             color: #dc3545;
             margin-top: 15px;
             font-weight: bold;
         }
     </style>
 </head>
 <body>
     <div class="login-container">
         <h2>需要登录</h2>
         <p>请输入您的凭据以访问 Docker 代理。</p>
         <form action="/login" method="post">
             <label for="username">用户名:</label>
             <input type="text" id="username" name="username" required>
             <label for="password">密码:</label>
             <input type="password" id="password" name="password" required>
             <button type="submit">登录</button>
         </form>
         ${errorHtml}
     </div>
 </body>
 </html>
 `;
    return new Response(html, {
        status: 401, // Unauthorized
        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
    });
}

/**
 * 处理 /login 的 POST 请求。
 * @param {Request} request
 * @param {object} env - 环境变量
 * @returns {Promise<Response>}
 */
async function handleLogin(request, env) {
    if (!env.AUTH_USERNAME || !env.AUTH_PASSWORD) {
        console.error("身份验证环境变量 (AUTH_USERNAME, AUTH_PASSWORD) 未设置。");
        return new Response("身份验证后端配置错误。", { status: 500 });
    }
    try {
        const formData = await request.formData();
        const username = formData.get('username');
        const password = formData.get('password');

        if (username === env.AUTH_USERNAME && password === env.AUTH_PASSWORD) {
            const token = await generateAuthToken(env.AUTH_USERNAME, env.AUTH_PASSWORD);
            const cookieValue = `${AUTH_COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`;
            return new Response(null, {
                status: 302, // Found (Redirect)
                headers: {
                    'Location': '/',
                    'Set-Cookie': cookieValue,
                },
            });
        } else {
            console.log("登录失败: 凭据无效");
            return generateLoginPage("用户名或密码无效。");
        }
    } catch (error) {
        console.error("处理登录表单时出错:", error);
        return generateLoginPage("登录过程中发生错误。");
    }
}

/**
 * 根据凭据哈希生成简单的身份验证令牌。
 * @param {string} username
 * @param {string} password
 * @returns {Promise<string>} - SHA-256 哈希的十六进制表示。
 */
async function generateAuthToken(username, password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(username + ':' + password);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(digest));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

/**
 * 检查当前请求是否通过 cookie 进行了身份验证。
 * @param {Request} request
 * @param {object} env - 环境变量
 * @returns {Promise<boolean>}
 */
async function isAuthenticated(request, env) {
    if (!env.AUTH_USERNAME || !env.AUTH_PASSWORD) {
        return false;
    }
    const cookies = request.headers.get('Cookie') || '';
    const tokenMatch = cookies.match(new RegExp(`${AUTH_COOKIE_NAME}=([^;]+)`));
    const receivedToken = tokenMatch ? tokenMatch[1] : null;

    if (!receivedToken) {
        return false;
    }

    const expectedToken = await generateAuthToken(env.AUTH_USERNAME, env.AUTH_PASSWORD);
    return receivedToken === expectedToken;
}

// --- Original Helper Functions (Adapted) ---
function routeByHosts(host) {
    const routes = {
        "quay": "quay.io", "gcr": "gcr.io", "k8s-gcr": "k8s.gcr.io",
        "k8s": "registry.k8s.io", "ghcr": "ghcr.io", "cloudsmith": "docker.cloudsmith.io",
        "nvcr": "nvcr.io", "test": "registry-1.docker.io",
    };
    if (host in routes) return [ routes[host], false ];
    else return [ hub_host, true ];
}

const PREFLIGHT_INIT = {
    headers: new Headers({
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
        'access-control-max-age': '1728000',
    }),
};

function makeRes(body, status = 200, headers = {}) {
    headers['access-control-allow-origin'] = '*';
    return new Response(body, { status, headers });
}

function newUrl(urlStr) {
    try { return new URL(urlStr); } catch (err) { return null; }
}

function isUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
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
<p>For online documentation and support please refer to<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at<a href="http://nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>
`;
    return text;
}

async function searchInterface() {
    const text = `<!DOCTYPE html>
<html>
<head>
<title>Docker Proxy Search</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta charset="UTF-8">
<style>
body {
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
display: flex;
flex-direction: column;
justify-content: center;
align-items: center;
min-height: 100vh;
background: linear-gradient(to bottom right, #001f3f, #0074D9);
margin: 0;
color: white;
}
.logo {
margin-bottom: 30px;
}
.search-container {
display: flex;
align-items: center;
background-color: rgba(255, 255, 255, 0.1);
padding: 5px;
border-radius: 25px;
box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
width: 80%;
max-width: 500px;
}
#search-input {
flex-grow: 1;
padding: 10px 20px;
border: none;
outline: none;
font-size: 16px;
background: transparent;
color: white;
}
#search-input::placeholder {
color: rgba(255, 255, 255, 0.7);
}
#search-button {
background: transparent;
border: none;
border-radius: 50%;
cursor: pointer;
width: 44px;
height: 44px;
display: flex;
align-items: center;
justify-content: center;
transition: background-color 0.2s ease;
margin-left: 5px;
}
#search-button:hover {
background-color: rgba(255, 255, 255, 0.2);
}
#search-button svg {
width: 24px;
height: 24px;
}
</style>
</head>
<body>
<div class="logo">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 18" fill="#ffffff" width="100" height="75">
<path d="M23.763 6.886c-.065-.053-.673-.512-1.954-.512-.32 0-.659.03-1.01.087-.248-1.703-1.651-2.533-1.716-2.57l-.345-.2-.227.328a4.596 4.596 0 0 0-.611 1.433c-.23.972-.09 1.884.403 2.666-.596.331-1.546.418-1.744.42H.752a.753.753 0 0 0-.75.749c-.007 1.456.233 2.864.692 4.07.545 1.43 1.355 2.483 2.409 3.13 1.181.725 3.104 1.14 5.276 1.14 1.016 0 2.03-.092 2.93-.266 1.417-.273 2.705-.742 3.826-1.391a10.497 10.497 0 0 0 2.61-2.14c1.252-1.42 1.998-3.005 2.553-4.408.075.003.148.005.221.005 1.371 0 2.215-.55 2.68-1.01.505-.5.685-.998.704-1.053L24 7.076l-.237-.19Z"></path>
<path d="M2.216 8.075h2.119a.186.186 0 0 0 .185-.186V6a.186.186 0 0 0-.185-.186H2.216A.186.186 0 0 0 2.031 6v1.89c0 .103.083.186.185.186Zm2.92 0h2.118a.185.185 0 0 0 .185-.186V6a.185.185 0 0 0-.185-.186H5.136A.185.185 0 0 0 4.95 6v1.89c0 .103.083.186.186.186Zm2.964 0h2.118a.186.186 0 0 0 .185-.186V6a.186.186 0 0 0-.185-.186H8.1A.185.185 0 0 0 7.914 6v1.89c0 .103.083.186.186.186Zm2.928 0h2.119a.185.185 0 0 0 .185-.186V6a.185.185 0 0 0-.185-.186h-2.119a.186.186 0 0 0-.185.186v1.89c0 .103.083.186.185.186Zm-5.892-2.72h2.118a.185.185 0 0 0 .185-.186V3.28a.186.186 0 0 0-.185-.186H5.136a.186.186 0 0 0-.186.186v1.89c0 .103.083.186.186.186Zm2.964 0h2.118a.186.186 0 0 0 .185-.186V3.28a.186.186 0 0 0-.185-.186H8.1a.186.186 0 0 0-.186.186v1.89c0 .103.083.186.186.186Zm2.928 0h2.119a.185.185 0 0 0 .185-.186V3.28a.186.186 0 0 0-.185-.186h-2.119a.186.186 0 0 0-.185.186v1.89c0 .103.083.186.185.186Zm0-2.72h2.119a.186.186 0 0 0 .185-.186V.56a.185.185 0 0 0-.185-.186h-2.119a.186.186 0 0 0-.185.186v1.89c0 .103.083.186.185.186Zm2.955 5.44h2.118a.185.185 0 0 0 .186-.186V6a.185.185 0 0 0-.186-.186h-2.118a.185.185 0 0 0-.185.186v1.89c0 .103.083.186.185.186Z"></path>
</svg>
</div>
<div class="search-container">
<input type="text" id="search-input" placeholder="搜索 Docker Hub 镜像...">
<button id="search-button">
<svg focusable="false" aria-hidden="true" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M21 21L16.65 16.65M19 11C19 15.4183 15.4183 19 11 19C6.58172 19 3 15.4183 3 11C3 6.58172 6.58172 3 11 3C15.4183 3 19 6.58172 19 11Z" stroke="white" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
</svg>
</button>
</div>
<script>
function performSearch() {
const query = document.getElementById('search-input').value;
if (query) {
window.location.href = '/search?q=' + encodeURIComponent(query);
}
}
document.getElementById('search-button').addEventListener('click', performSearch);
document.getElementById('search-input').addEventListener('keypress', function(event) {
if (event.key === 'Enter') {
performSearch();
}
});
</script>
</body>
</html>`;
    return text;
}

// --- Main Fetch Handler ---
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        workers_url = `https://${url.hostname}`; // 动态设置 worker URL

        // --- Uptime Kuma Health Check ---
        if (url.pathname === '/status') {
            return new Response('OK', { status: 200 });
        }

        // --- Authentication Check ---
        if (url.pathname === '/login' && request.method === 'POST') {
            return handleLogin(request, env);
        }

        const authenticated = await isAuthenticated(request, env);
        if (!authenticated) {
            if (url.pathname === '/login' && request.method === 'GET') {
                return generateLoginPage();
            }
            console.log(`需要身份验证: ${url.pathname}`);
            return generateLoginPage();
        }

        console.log(`已验证访问: ${url.pathname}`);

        const getReqHeader = (key) => request.headers.get(key);
        const userAgentHeader = request.headers.get('User-Agent');
        const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : "null";
        if (env.UA) {
            try {
                屏蔽爬虫UA = 屏蔽爬虫UA.concat(await ADD(env.UA));
            } catch (e) {
                console.error("处理 env.UA 时出错:", e);
            }
        }

        const pathname = url.pathname;
        const ns = url.searchParams.get('ns');
        const requestHostname = request.headers.get('Host') || url.hostname;
        const hostTop = requestHostname.split('.')[0];

        let checkHost;
        if (ns) {
            hub_host = (ns === 'docker.io') ? 'registry-1.docker.io' : ns;
            checkHost = routeByHosts(null);
            checkHost[0] = hub_host;
        } else {
            hub_host = 'registry-1.docker.io';
            checkHost = routeByHosts(hostTop);
            hub_host = checkHost[0];
        }

        const fakePage = checkHost ? checkHost[1] : false;
        console.log(`域名头部: ${hostTop}\n反代地址: ${hub_host}\n伪装首页: ${fakePage}`);
        const isUuid = isUUID(pathname.split('/')[1]?.split('/')[0] || '');

        if (屏蔽爬虫UA.some(fxxk => userAgent.includes(fxxk)) && 屏蔽爬虫UA.length > 0) {
            return new Response(await nginx(), {
                headers: { 'Content-Type': 'text/html; charset=UTF-8' },
            });
        }

        const conditions = [
            isUuid,
            pathname.includes('/_'), pathname.includes('/r/'), pathname.includes('/v2/repositories'),
            pathname.includes('/v2/user'), pathname.includes('/v2/orgs'), pathname.includes('/v2/_catalog'),
            pathname.includes('/v2/categories'), pathname.includes('/v2/feature-flags'),
            pathname.includes('search'), pathname.includes('source'), pathname === '/',
            pathname === '/favicon.ico', pathname === '/auth/profile',
        ];

        if (conditions.some(condition => condition) && (fakePage === true || hostTop === 'docker')) {
            if (env.URL302) {
                return Response.redirect(env.URL302, 302);
            } else if (env.URL) {
                if (env.URL.toLowerCase() === 'nginx') {
                    return new Response(await nginx(), {
                        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
                    });
                } else {
                    return fetch(new Request(env.URL, request));
                }
            } else if (url.pathname === '/') {
                return new Response(await searchInterface(), {
                    headers: { 'Content-Type': 'text/html; charset=UTF-8' },
                });
            }

            console.log(`将 UI/搜索请求代理到 registry.hub.docker.com: ${pathname}`);
            const newUrl = new URL("https://registry.hub.docker.com" + pathname + url.search);
            const headers = new Headers(request.headers);
            headers.set('Host', 'registry.hub.docker.com');
            const newRequest = new Request(newUrl, {
                method: request.method,
                headers: headers,
                body: request.method !== 'GET' && request.method !== 'HEAD' ? await request.blob() : null,
                redirect: 'follow'
            });
            return fetch(newRequest);
        }

        if (hub_host === 'registry-1.docker.io' && /^\/v2\/[^/]+\/[^/]+\/[^/]+$/.test(pathname) && !/^\/v2\/library/.test(pathname)) {
            url.pathname = '/v2/library/' + pathname.split('/v2/')[1];
            console.log(`为 library 命名空间修改了 URL 路径: ${url.pathname}`);
        }

        if (pathname.includes('/token')) {
            let token_url = auth_url + pathname + url.search;
            console.log(`将令牌请求转发到: ${token_url}`);
            const tokenHeaders = new Headers(request.headers);
            tokenHeaders.set('Host', 'auth.docker.io');
            tokenHeaders.delete('Cookie');
            const tokenRequest = new Request(token_url, {
                method: request.method,
                headers: tokenHeaders,
                body: request.body,
                redirect: request.redirect
            });
            return fetch(tokenRequest);
        }

        const proxyUrl = new URL(url);
        proxyUrl.hostname = hub_host;
        console.log(`将请求代理到: ${proxyUrl.toString()}`);

        const upstreamHeaders = new Headers(request.headers);
        upstreamHeaders.set('Host', hub_host);
        upstreamHeaders.delete('Cookie');
        if (request.headers.has("Authorization")) {
            upstreamHeaders.set("Authorization", getReqHeader("Authorization"));
        }

        const upstreamRequest = new Request(proxyUrl.toString(), {
            method: request.method,
            headers: upstreamHeaders,
            body: request.body,
            redirect: 'manual'
        });

        let original_response = await fetch(upstreamRequest, { cf: { cacheTtl: 3600 } });
        let original_response_clone = original_response.clone();
        let response_headers = original_response.headers;
        let new_response_headers = new Headers(response_headers);
        let status = original_response.status;

        if (new_response_headers.get("Www-Authenticate")) {
            let authHeader = new_response_headers.get("Www-Authenticate");
            authHeader = authHeader.replace(/realm="[^"]*"/, `realm="${workers_url}/token"`);
            authHeader = authHeader.replace(/service="[^"]*"/, `service="${hub_host}"`);
            new_response_headers.set("Www-Authenticate", authHeader);
            console.log(`修改后的 Www-Authenticate 头: ${authHeader}`);
        }

        if (status >= 300 && status < 400 && new_response_headers.has("Location")) {
            const location = new_response_headers.get("Location");
            console.log(`处理重定向: ${status} 到 ${location}`);
            return new Response(null, {
                status: status,
                headers: new_response_headers
            });
        }

        new_response_headers.set('access-control-allow-origin', '*');
        new_response_headers.set('access-control-expose-headers', '*');

        return new Response(original_response_clone.body, {
            status,
            headers: new_response_headers
        });
    }
};

// --- Utility Functions ---
async function ADD(envadd) {
    var addtext = envadd.replace(/[ \t|"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (addtext.startsWith(',')) addtext = addtext.slice(1);
    if (addtext.endsWith(',')) addtext = addtext.slice(0, -1);
    return addtext.split(',').filter(Boolean);
}
