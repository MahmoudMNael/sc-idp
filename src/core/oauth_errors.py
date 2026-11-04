from urllib.parse import urlencode

from fastapi.responses import JSONResponse, RedirectResponse


def token_error(error: str, description: str | None = None, status: int = 400) -> JSONResponse:
    body = {"error": error}
    if description:
        body["error_description"] = description
    return JSONResponse(body, status_code=status)


def append_query(url: str, **params: str | None) -> str:
    clean = {k: v for k, v in params.items() if v is not None}
    sep = "&" if "?" in url else "?"
    return url + sep + urlencode(clean)


def oauth_redirect(redirect_uri: str, **params: str | None) -> RedirectResponse:
    return RedirectResponse(append_query(redirect_uri, **params), status_code=302)
