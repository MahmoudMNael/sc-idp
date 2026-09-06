from pathlib import Path

from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from idp.crypto import new_csrf
from idp.sessions import set_csrf_cookie
from idp.settings import Settings

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def page(request: Request, settings: Settings, name: str, status: int = 200, **ctx):
    csrf = new_csrf(settings.secret_key)
    response = templates.TemplateResponse(
        request, name, {"csrf": csrf, **ctx}, status_code=status
    )
    set_csrf_cookie(response, settings, csrf)
    return response
