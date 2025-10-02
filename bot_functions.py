"""
Модуль основных функций бота для анализа безопасности веб-сайтов.
"""

from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import json

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import WebDriverException
from webdriver_manager.chrome import ChromeDriverManager

from config import Config
from logs import logger
from security_analyzer import SecurityAnalyzer


class BotFunctions:
    """Класс основных функций бота безопасности."""

    @staticmethod
    def create_driver() -> webdriver.Chrome:
        """
        Создает и настраивает экземпляр Chrome WebDriver.

        Returns:
            webdriver.Chrome: Настроенный экземпляр WebDriver

        Raises:
            WebDriverException: Если не удалось создать WebDriver
        """
        chrome_options = Options()

        # Опции безопасности
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-popup-blocking')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_argument('--disable-infobars')

        # Скрываем автоматизацию
        chrome_options.add_experimental_option('excludeSwitches', ['enable-automation'])
        chrome_options.add_experimental_option('useAutomationExtension', False)

        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            driver.set_page_load_timeout(Config.REQUEST_TIMEOUT)

            logger.info("Инициализирован новый WebDriver")
            return driver

        except WebDriverException as e:
            logger.error(f"Ошибка создания WebDriver: {str(e)}")
            raise

    @staticmethod
    def check_virustotal(url: str) -> Dict[str, Any]:
        """
        Проверяет URL через VirusTotal API.

        Args:
            url: URL для проверки

        Returns:
            Dict с результатами проверки или пустой словарь при ошибке
        """
        if not Config.VIRUSTOTAL_API_KEY or Config.VIRUSTOTAL_API_KEY.startswith('YOUR_'):
            logger.warning("VirusTotal API ключ не настроен")
            return {}

        params = {
            'apikey': Config.VIRUSTOTAL_API_KEY,
            'resource': url,
            'scan': 1
        }

        try:
            response = requests.get(
                'https://www.virustotal.com/vtapi/v2/url/report',
                params=params,
                timeout=Config.REQUEST_TIMEOUT
            )
            response.raise_for_status()

            return response.json()

        except requests.exceptions.RequestException as e:
            logger.warning(f"Ошибка подключения к VirusTotal: {str(e)}")
            return {}
        except ValueError as e:
            logger.warning(f"VirusTotal вернул невалидный JSON для URL {url}: {str(e)}")
            return {}
        except Exception as e:
            logger.error(f"Неожиданная ошибка VirusTotal: {str(e)}")
            return {}

    @staticmethod
    def build_report_message(url: str, analysis: Dict[str, Any]) -> str:
        """
        Формирует читаемое сообщение с отчетом о безопасности.

        Args:
            url: Анализируемый URL
            analysis: Результаты анализа безопасности

        Returns:
            str: Отформатированное сообщение с отчетом
        """
        safety_level, color = SecurityAnalyzer.calculate_safety_level(analysis)

        # Безопасное форматирование значений
        domain_age = analysis['domain_checks'].get('domain_age_days', 'N/A')
        if isinstance(domain_age, int):
            domain_age = f"{domain_age} дней"

        ssl_days = analysis['domain_checks'].get('ssl_valid_days', 'N/A')
        if isinstance(ssl_days, int):
            ssl_days = f"{ssl_days} дней"

        report_msg = f"🔍 Анализ безопасности для {url}\n\n"
        report_msg += f"📊 Уровень безопасности: {safety_level}\n\n"

        report_msg += "🔎 Основные проверки:\n"
        report_msg += f"🔐 SSL: {'✅ Да' if analysis['basic_checks']['has_ssl'] else '❌ Нет'}\n"
        report_msg += f"📅 Возраст домена: {domain_age}\n"
        report_msg += f"📆 SSL действителен: {ssl_days}\n"
        report_msg += f"🏷 Заголовок: {analysis['basic_checks']['page_title']}\n\n"

        report_msg += "🛡 Показатели фишинга:\n"
        report_msg += f"🔑 Поля пароля: {analysis['phishing_indicators']['password_fields']}\n"
        report_msg += f"👀 Скрытые элементы: {analysis['phishing_indicators']['hidden_elements']}\n"
        report_msg += f"📜 Подозрительные скрипты: {analysis['phishing_indicators']['suspicious_scripts']}\n"

        if analysis['warnings']:
            report_msg += "\n⚠️ Предупреждения:\n" + "\n".join(
                f"• {warning}" for warning in analysis['warnings'])

        # Рекомендации по уровню безопасности
        if color == "green":
            report_msg += "\n\n✅ Этот сайт выглядит безопасным."
        elif color == "yellow":
            report_msg += "\n\n⚠️ Будьте осторожны! Сайт содержит подозрительные элементы."
        else:
            report_msg += "\n\n❌ Внимание! Сайт может представлять угрозу."

        return report_msg

    @staticmethod
    def log_action(user_id: int, action: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Логирует действия пользователя.

        Args:
            user_id: ID пользователя Telegram
            action: Тип действия
            details: Дополнительные детали действия
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'action': action,
            'details': details or {}
        }

        logger.info(f"Действие пользователя: {json.dumps(log_entry, ensure_ascii=False)}")