# app/calendar_utils.py
from google_auth_oauthlib.flow import Flow

def create_flow(settings):
    client_config = {
        "web": {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [f"{settings.BACKEND_URL}/calendar/oauth2callback"],
        }
    }
    flow = Flow.from_client_config(
        client_config,
        # calendar.events wystarcza do tworzenia/edycji wydarzeń, ale NIE do
        # colors.get() — ten zwraca 403 "insufficient authentication scopes"
        # bez calendar.readonly. Konta połączone PRZED tą zmianą muszą się
        # rozłączyć i połączyć ponownie, żeby dostać nowy zakres zgody.
        scopes=[
            "https://www.googleapis.com/auth/calendar.events",
            "https://www.googleapis.com/auth/calendar.readonly",
        ],
    )
    flow.redirect_uri = f"{settings.BACKEND_URL}/calendar/oauth2callback"
    return flow
