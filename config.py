"""
Конфигурационные настройки бота безопасности.

ВНИМАНИЕ: Замените значения на свои перед использованием!
Для production используйте переменные окружения.
"""

import os
from typing import Optional


class Config:
    """Конфигурационные параметры приложения."""

    # Bot Configuration
    BOT_TOKEN: str = os.getenv('BOT_TOKEN', '')

    # API Keys
    VIRUSTOTAL_API_KEY: str = os.getenv(
        'VIRUSTOTAL_API_KEY',
        ''
    )
    GOOGLE_SAFE_BROWSING_KEY: Optional[str] = os.getenv('GOOGLE_SAFE_BROWSING_KEY', '')

    # Timeout Settings
    REQUEST_TIMEOUT: int = 30
    WHOIS_TIMEOUT: int = 5

    # Quality Settings
    SCREENSHOT_QUALITY: int = 85