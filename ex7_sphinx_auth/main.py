import httpx
from clerk_backend_api import Clerk
from clerk_backend_api.jwks_helpers import AuthenticateRequestOptions
from decouple import config
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

CLERK_SECRET_KEY = config("CLERK_SECRET_KEY")
ENVIRONMENT = config("ENVIRONMENT", default="production")
DOMAIN = config("DOMAIN")
CLERK_DOMAIN = config("CLERK_DOMAIN")
APP_URL_VERCEL = config("APP_URL_VERCEL")
# Initialize FastAPI app
app = FastAPI()

# Set up CORS middleware with allowed origins (used by the Clerk frontend)
allowed_origins = [
    f"https://{CLERK_DOMAIN}",
    f"https://{DOMAIN}",
    f"https://{APP_URL_VERCEL}",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Custom middleware to protect routes based on Clerk authentication and authorization.
@app.middleware("http")
async def clerk_auth_middleware(request: Request, call_next):
    # 调试：打印请求 URL 和请求头
    print("DEBUG: Request URL:", request.url)
    print("DEBUG: Request Headers:", dict(request.headers))

    if request.method.lower() == "options":
        return await call_next(request)

    unprotected_paths = ["/login.html", "/favicon.ico"]
    if any(request.url.path.startswith(path) for path in unprotected_paths):
        print("DEBUG: Unprotected path, skipping auth.")
        return await call_next(request)

    # 实例化 Clerk SDK
    clerk = Clerk(bearer_auth=CLERK_SECRET_KEY)

    # 将 FastAPI 的请求转换为 httpx.Request
    client_request = httpx.Request(
        method=request.method,
        url=str(request.url),
        headers=dict(request.headers)
    )

    # 根据环境设置授权列表
    if ENVIRONMENT == "development":
        authorized_parties = [
            f"https://{CLERK_DOMAIN}",
            f"https://{DOMAIN}",
            f"https://{APP_URL_VERCEL}",
            "http://0.0.0.0:8000",
            "http://localhost:8000",
        ]
    else:
        authorized_parties = [
            f"https://{CLERK_DOMAIN}",
            f"https://{DOMAIN}",
            f"https://{APP_URL_VERCEL}",
        ]
    print("DEBUG: Authorized parties:", authorized_parties)

    options = AuthenticateRequestOptions(authorized_parties=authorized_parties)

    # 尝试验证请求
    try:
        auth_state = clerk.authenticate_request(client_request, options)
        print("DEBUG: Auth state:", auth_state)
    except Exception as e:
        print("DEBUG: Exception during authentication:", str(e))
        return RedirectResponse(url="/login.html")

    # 判断是否登录
    if not auth_state.is_signed_in:
        print("DEBUG: User not signed in.")
        return RedirectResponse(url="/login.html")

    # 从 Token 中获取用户 ID
    user_id = auth_state.payload.get("sub")
    print("DEBUG: User ID from token:", user_id)

    # 获取用户完整信息
    try:
        user = clerk.users.get(user_id=user_id)
        print("DEBUG: User public_metadata:", user.public_metadata)
    except Exception as e:
        print("DEBUG: Exception fetching user info:", str(e))
        return RedirectResponse(url="/login.html")

    # 检查用户权限
    if user.public_metadata.get("isCustomer"):
        print("DEBUG: User is authorized, processing request.")
        response = await call_next(request)
        return response
    else:
        print("DEBUG: User is NOT authorized.")
        return RedirectResponse(url="/login.html")


# Mount the "main" directory to serve static files (including index.html, login.html, etc.)
# app.mount("/", StaticFiles(directory="./main", html=True), name="main")
app.mount("/", StaticFiles(directory="./ex7_sphinx_auth/main", html=True), name="main")