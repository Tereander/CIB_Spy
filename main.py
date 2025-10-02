"""
Главный модуль Telegram бота для проверки безопасности веб-сайтов.

Бот анализирует URL на признаки фишинга, делает скриншоты
и предоставляет отчет о безопасности.
"""

import locale
from typing import Optional

import telebot
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.wait import WebDriverWait

from config import Config
from logs import logger
from bot_functions import BotFunctions
from security_analyzer import SecurityAnalyzer


# Настройка локали
try:
    locale.setlocale(locale.LC_ALL, 'ru_RU.UTF-8')
except locale.Error:
    try:
        locale.setlocale(locale.LC_ALL, '')
    except locale.Error:
        logger.warning("Не удалось установить локаль")


# Инициализация бота
bot = telebot.TeleBot(Config.BOT_TOKEN)


@bot.message_handler(commands=['start', 'help'])
def send_welcome(message: telebot.types.Message) -> None:
    """
    Обработчик команд /start и /help.

    Args:
        message: Объект сообщения от пользователя
    """
    help_text = """
🔐 Бот для проверки безопасности веб-сайтов

Просто отправьте URL (ссылку), и я:
1. 📸 Сделаю скриншот страницы
2. 🔍 Проверю на признаки фишинга  
3. 📊 Проанализирую содержимое
4. 🛡️ Дам оценку безопасности

Пример: https://example.com

Команды:
/start - начать работу
/help - показать эту справку
"""
    bot.reply_to(message, help_text)
    BotFunctions.log_action(message.from_user.id, 'start_command')


@bot.message_handler(func=lambda message: True)
def handle_url(message: telebot.types.Message) -> None:
    """
    Основной обработчик URL сообщений.

    Args:
        message: Объект сообщения с URL
    """
    user_id: int = message.from_user.id
    url: str = message.text.strip()

    try:
        BotFunctions.log_action(user_id, 'url_received', {'url': url})

        # Валидация URL
        if not _is_valid_url(url):
            error_msg: str = "❌ URL должен начинаться с http:// или https://"
            bot.reply_to(message, error_msg)
            BotFunctions.log_action(user_id, 'invalid_url', {'error': error_msg})
            return

        # Отправка действия "печатает"
        _send_typing_action(message.chat.id)

        # Проверка VirusTotal
        vt_report: dict = BotFunctions.check_virustotal(url)
        if vt_report.get('positives', 0) > 0:
            warning: str = (
                f"⚠️ VirusTotal обнаружил {vt_report['positives']} угроз. "
                "Продолжаю сканирование..."
            )
            bot.send_message(message.chat.id, warning)

        # Основной анализ
        driver = None
        try:
            _send_typing_action(message.chat.id)
            driver = BotFunctions.create_driver()
            logger.info(f"Загрузка страницы: {url}")

            # Настройка таймаутов
            driver.set_page_load_timeout(Config.REQUEST_TIMEOUT)
            driver.set_script_timeout(Config.REQUEST_TIMEOUT)

            # Загрузка страницы
            driver.get(url)

            # Ожидание загрузки
            WebDriverWait(driver, Config.REQUEST_TIMEOUT).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )

            # Анализ безопасности
            analysis: dict = SecurityAnalyzer.analyze_page_security(driver, url)
            screenshot: bytes = driver.get_screenshot_as_png()
            safety_level, color = SecurityAnalyzer.calculate_safety_level(analysis)

            # Формирование сообщения
            prefix: str = _get_safety_prefix(color)
            report_msg: str = prefix + BotFunctions.build_report_message(url, analysis)

            # Отправка результата
            bot.send_photo(
                chat_id=message.chat.id,
                photo=screenshot,
                caption=report_msg
            )

            BotFunctions.log_action(user_id, 'analysis_completed', {
                'url': url,
                'safety_level': safety_level,
                'warnings_count': len(analysis['warnings'])
            })

        except TimeoutException:
            error_msg = "🕒 Превышено время ожидания загрузки страницы"
            bot.reply_to(message, error_msg)
            logger.warning(f"Таймаут для URL: {url}")
            BotFunctions.log_action(user_id, 'timeout_error', {'url': url})

        except Exception as e:
            error_msg = f"❌ Ошибка при обработке URL: {str(e)}"
            bot.reply_to(message, error_msg)
            logger.error(f"Ошибка обработки URL: {url} - {str(e)}")
            BotFunctions.log_action(user_id, 'processing_error', {
                'url': url,
                'error': str(e)
            })

        finally:
            if driver:
                driver.quit()

    except Exception as e:
        error_msg = f"❌ Системная ошибка: {str(e)}"
        bot.reply_to(message, error_msg)
        logger.critical(f"Критическая ошибка: {str(e)}")
        BotFunctions.log_action(user_id, 'system_error', {'error': str(e)})


def _is_valid_url(url: str) -> bool:
    """
    Проверяет валидность URL.

    Args:
        url: URL для проверки

    Returns:
        bool: True если URL валиден
    """
    return url.startswith(('http://', 'https://'))


def _send_typing_action(chat_id: int) -> None:
    """
    Отправляет действие 'печатает' в чат.

    Args:
        chat_id: ID чата
    """
    try:
        bot.send_chat_action(chat_id, 'typing')
    except Exception as e:
        logger.warning(f"Не удалось отправить chat action: {str(e)}")


def _get_safety_prefix(color: str) -> str:
    """
    Возвращает префикс для сообщения в зависимости от уровня безопасности.

    Args:
        color: Цветовой код уровня безопасности

    Returns:
        str: Emoji префикс
    """
    prefixes = {
        "green": "✅ ",
        "yellow": "⚠️ ",
        "orange": "🟠 ",
        "red": "❌ "
    }
    return prefixes.get(color, "🔍 ")


def main() -> None:
    """Основная функция запуска бота."""
    logger.info("Запуск бота безопасности...")

    try:
        bot.infinity_polling(timeout=60, long_polling_timeout=30)
    except KeyboardInterrupt:
        logger.info("Бот остановлен пользователем")
    except Exception as e:
        logger.critical(f"Критическая ошибка бота: {str(e)}")
        raise


if __name__ == '__main__':
    main()