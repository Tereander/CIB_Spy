"""
Настройка логирования для бота безопасности.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


def setup_logging(log_file: Optional[str] = None) -> logging.Logger:
    """
    Настраивает логирование для приложения.

    Args:
        log_file: Путь к файлу логов. Если None, используется значение по умолчанию.

    Returns:
        logging.Logger: Настроенный логгер
    """
    logger = logging.getLogger('security_bot')
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Создаем директорию для логов если нужно
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        log_file = 'logs/bot_security.log'
        Path('logs').mkdir(exist_ok=True)

    # File handler с ротацией
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=3,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# Глобальный логгер
logger = setup_logging()