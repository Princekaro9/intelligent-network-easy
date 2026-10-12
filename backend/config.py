from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Intelligent Network Packet Analyzer"
    app_env: str = "development"
    app_secret: str = ""

    supabase_url: str = ""
    supabase_key: str = ""

    external_api_key: str = ""
    ai_api_key: str = ""
    websocket_secret: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
