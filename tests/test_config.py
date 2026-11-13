from __future__ import annotations

from pathlib import Path

from app import config


def test_frontend_and_backend_resolve_same_api_key_from_env_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / ".env").write_text(
        "PRIVACYSHIELD_API_KEY=fictional-file-key\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(config, "load_dotenv", lambda *_args, **_kwargs: None)
    monkeypatch.delenv("PRIVACYSHIELD_API_KEY", raising=False)
    monkeypatch.setenv("PRIVACYSHIELD_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PRIVACYSHIELD_DATABASE_PATH", str(tmp_path / "data" / "test.db"))

    frontend_key = config.dashboard_api_key()
    backend_key = config.Settings.from_env().api_key

    assert frontend_key == backend_key == "fictional-file-key"


def test_frontend_and_backend_use_same_process_key_precedence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / ".env").write_text(
        "PRIVACYSHIELD_API_KEY=fictional-file-key\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(config, "load_dotenv", lambda *_args, **_kwargs: None)
    monkeypatch.setenv("PRIVACYSHIELD_API_KEY", "fictional-process-key")
    monkeypatch.setenv("PRIVACYSHIELD_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PRIVACYSHIELD_DATABASE_PATH", str(tmp_path / "data" / "test.db"))

    assert config.dashboard_api_key() == config.Settings.from_env().api_key
    assert config.dashboard_api_key() == "fictional-process-key"


def test_blank_process_key_falls_back_to_nonempty_env_file_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / ".env").write_text(
        "PRIVACYSHIELD_API_KEY=fictional-file-key\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(config, "load_dotenv", lambda *_args, **_kwargs: None)
    monkeypatch.setenv("PRIVACYSHIELD_API_KEY", "  ")
    monkeypatch.setenv("PRIVACYSHIELD_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PRIVACYSHIELD_DATABASE_PATH", str(tmp_path / "data" / "test.db"))

    assert config.dashboard_api_key() == config.Settings.from_env().api_key
    assert config.dashboard_api_key() == "fictional-file-key"


def test_llm_api_key_loads_from_environment_without_appearing_in_settings_repr(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("LLM_API_KEY", "fictional-llm-secret")
    monkeypatch.setenv("PRIVACYSHIELD_API_KEY", "fictional-backend-secret")
    monkeypatch.setenv("PRIVACYSHIELD_ENCRYPTION_KEY", "fictional-encryption-secret")
    monkeypatch.setenv("PRIVACYSHIELD_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PRIVACYSHIELD_DATABASE_PATH", str(tmp_path / "data" / "test.db"))

    settings = config.Settings.from_env()

    assert settings.llm_api_key == "fictional-llm-secret"
    assert all(
        secret not in repr(settings)
        for secret in (
            "fictional-llm-secret",
            "fictional-backend-secret",
            "fictional-encryption-secret",
        )
    )
