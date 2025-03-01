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
    # Allow preflight OPTIONS requests (handled by CORS middleware)
    if request.method.lower() == "options":
        return await call_next(request)

    # Define paths that should bypass authentication (e.g. login and favicon)
    unprotected_paths = ["/login.html", "/favicon.ico"]
    if any(request.url.path.startswith(path) for path in unprotected_paths):
        return await call_next(request)

    # Instantiate the Clerk SDK.
    # (If desired, you could instantiate this once globally if it is thread‐safe.)
    clerk = Clerk(bearer_auth=CLERK_SECRET_KEY)

    # Convert the FastAPI request into an httpx.Request so that it can be passed to Clerk's helper.
    # (We pass the method, URL, and headers – assuming that Clerk can extract the token from headers or cookies.)
    client_request = httpx.Request(
        method=request.method, url=str(request.url), headers=dict(request.headers)
    )

    # Set up the options for request authentication.
    # Here, we allow only tokens issued for our own app (for example "http://0.0.0.0:8000").
    if ENVIRONMENT == "development":
        authorized_parties = [
            # "https://example.com",
            f"https://{CLERK_DOMAIN}",
            f"https://{DOMAIN}",
            f"https://{APP_URL_VERCEL}",
            "http://0.0.0.0:8000",
            "http://localhost:8000",
        ]
    else:
        authorized_parties = [
            # "https://example.com",
            f"https://{CLERK_DOMAIN}",
            f"https://{DOMAIN}",
            f"https://{APP_URL_VERCEL}",
        ]
    options = AuthenticateRequestOptions(authorized_parties=authorized_parties)

    try:
        auth_state = clerk.authenticate_request(client_request, options)
    except Exception:
        # In case of error or exception, log it and redirect the user to the login page.
        return RedirectResponse(url="/login.html")

    # If the token is invalid (i.e. not signed in) then redirect to login page.
    if not auth_state.is_signed_in:
        return RedirectResponse(url="/login.html")

    # Get user ID from session claims
    user_id = auth_state.payload.get('sub')
    # Fetch full user details including metadata
    user = clerk.users.get(user_id=user_id)

    if user.public_metadata.get("isCustomer"):
        # Continue processing the request if authentication and authorization succeeded.
        response = await call_next(request)
        return response
    else:
        return RedirectResponse(url="/login.html")


# Mount the "main" directory to serve static files (including index.html, login.html, etc.)
# app.mount("/", StaticFiles(directory="./main", html=True), name="main")
app.mount("/", StaticFiles(directory="./ex7_sphinx_auth/main", html=True), name="main")