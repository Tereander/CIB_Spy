"""
Модуль анализа безопасности веб-страниц.

Содержит функции для проверки доменов, SSL, контента и репутации сайтов.
"""

import re
import socket
import ssl
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

import requests
from bs4 import BeautifulSoup
from OpenSSL import crypto
import whois
from whois.parser import PywhoisError

from config import Config
from logs import logger


def check_domain_and_ssl(url: str) -> Dict[str, Any]:
    """
    Проверяет домен и SSL сертификат.

    Args:
        url: URL для проверки

    Returns:
        Dict с информацией о домене и SSL
    """
    result = {
        'domain_age_days': None,
        'ssl_valid_days': None,
        'is_suspicious_domain': False
    }

    try:
        domain = urlparse(url).netloc
        if not domain:
            return result

        # Проверка WHOIS с таймаутом
        try:
            with ThreadPoolExecutor() as executor:
                future = executor.submit(whois.whois, domain)
                domain_info = future.result(timeout=Config.WHOIS_TIMEOUT)

                if domain_info and domain_info.creation_date:
                    creation_date = min(domain_info.creation_date) if isinstance(
                        domain_info.creation_date, list) else domain_info.creation_date
                    if creation_date:
                        age_days = (datetime.now() - creation_date).days
                        result['domain_age_days'] = age_days
                        if age_days < 30:
                            result['is_suspicious_domain'] = True
        except (FutureTimeoutError, PywhoisError, AttributeError) as e:
            logger.warning(f"WHOIS timeout/error for {domain}: {str(e)}")

        # Проверка SSL
        try:
            hostname = domain.split(':')[0]
            context = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
                    expire_bytes = x509.get_notAfter()

                    if expire_bytes:
                        expire_str = expire_bytes.decode('ascii')
                        expire_date = datetime.strptime(expire_str, '%Y%m%d%H%M%SZ')
                        result['ssl_valid_days'] = (expire_date - datetime.now()).days
        except Exception as e:
            logger.warning(f"SSL check error for {hostname}: {str(e)}")

    except Exception as e:
        logger.error(f"Domain/SSL check critical error: {str(e)}")

    return result


def analyze_content(soup: BeautifulSoup) -> Dict[str, Any]:
    """
    Анализирует контент страницы на подозрительные элементы.

    Args:
        soup: BeautifulSoup объект страницы

    Returns:
        Dict с результатами анализа контента
    """
    result = {
        'fake_login_forms': 0,
        'external_scripts': [],
        'iframe_count': 0,
        'popup_elements': 0
    }

    # Поиск поддельных форм входа
    for form in soup.find_all('form'):
        if (form.find('input', {'type': 'password'}) and
            not form.find('input', {'type': 'submit'})):
            result['fake_login_forms'] += 1

    # Подозрительные внешние скрипты
    for script in soup.find_all('script', src=True):
        if ('jquery' not in script['src'].lower() and
            'google' not in script['src'].lower()):
            result['external_scripts'].append(script['src'][:100])

    # Количество iframe
    result['iframe_count'] = len(soup.find_all('iframe'))

    # Элементы для popup
    result['popup_elements'] = len(
        soup.find_all(onclick=True) +
        soup.find_all(onmouseover=True)
    )

    return result


def check_reputation(url: str) -> Dict[str, Any]:
    """
    Проверяет репутацию сайта в различных сервисах.

    Args:
        url: URL для проверки

    Returns:
        Dict с результатами проверки репутации
    """
    result = {
        'google_safe_browsing': None,
        'phishtank_status': None,
        'is_blacklisted': False
    }

    try:
        # Google Safe Browsing
        if (hasattr(Config, 'GOOGLE_SAFE_BROWSING_KEY') and
            Config.GOOGLE_SAFE_BROWSING_KEY):
            try:
                payload = {
                    "client": {"clientId": "security-bot", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }
                response = requests.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
                    f"?key={Config.GOOGLE_SAFE_BROWSING_KEY}",
                    json=payload,
                    timeout=10
                )
                result['google_safe_browsing'] = bool(response.json().get('matches'))
            except Exception as e:
                logger.warning(f"Google Safe Browsing error: {str(e)}")

        # PhishTank проверка
        try:
            phishtank_response = requests.get(
                f"https://checkurl.phishtank.com/checkurl/?url={url}",
                headers={'User-Agent': 'SecurityBot'},
                timeout=10
            )
            if phishtank_response.ok:
                result['phishtank_status'] = 'phish' in phishtank_response.text.lower()
        except Exception as e:
            logger.warning(f"PhishTank error: {str(e)}")

        # Определяем blacklist статус
        safe_browsing = result['google_safe_browsing']
        phishtank = result['phishtank_status']

        if safe_browsing is not None or phishtank is not None:
            result['is_blacklisted'] = (
                (safe_browsing is True) or
                (phishtank is True)
            )

    except Exception as e:
        logger.error(f"Reputation check critical error: {str(e)}")

    return result


def heuristic_checks(url: str, page_source: str) -> Dict[str, Any]:
    """
    Эвристические проверки на фишинг и подозрительную активность.

    Args:
        url: URL для проверки
        page_source: Исходный код страницы

    Returns:
        Dict с результатами эвристических проверок
    """
    result = {
        'typosquatting': False,
        'brand_impersonation': False,
        'suspicious_keywords': 0
    }

    # Простые эвристики для демонстрации
    suspicious_keywords = ['login', 'password', 'verify', 'account', 'secure']
    for keyword in suspicious_keywords:
        if keyword in page_source.lower():
            result['suspicious_keywords'] += 1

    return result


class SecurityAnalyzer:
    """Анализатор безопасности веб-страниц."""

    @staticmethod
    def analyze_page_security(driver: Any, url: str) -> Dict[str, Any]:
        """
        Анализирует содержимое страницы на признаки фишинга.

        Args:
            driver: WebDriver экземпляр
            url: URL для анализа

        Returns:
            Dict с результатами анализа безопасности
        """
        analysis = {
            'basic_checks': {
                'has_ssl': url.startswith('https'),
                'domain': urlparse(url).netloc,
                'page_title': driver.title[:100]
            },
            'phishing_indicators': {
                'hidden_elements': 0,
                'password_fields': 0,
                'suspicious_scripts': 0,
                'external_resources': []
            },
            'warnings': [],
            'is_dangerous': False,
            'domain_checks': {},
            'content_analysis': {},
            'reputation': {},
            'heuristics': {}
        }

        try:
            soup = BeautifulSoup(driver.page_source, 'html.parser')

            # 1. Поиск скрытых элементов
            hidden_elements = []
            for tag in soup.find_all(style=True):
                if re.search(
                    r'display:\s*none|visibility:\s*hidden',
                    tag['style'],
                    re.IGNORECASE
                ):
                    hidden_elements.append(tag)
            analysis['phishing_indicators']['hidden_elements'] = len(hidden_elements)

            # 2. Поиск полей пароля
            analysis['phishing_indicators']['password_fields'] = len(
                soup.find_all('input', {'type': 'password'})
            )

            # 3. Поиск подозрительных скриптов
            dangerous_terms = [r'eval\(', r'fromCharCode', r'atob\(']
            suspicious_scripts = []
            for script in soup.find_all('script'):
                if script.string:
                    for term in dangerous_terms:
                        if re.search(term, script.string, re.IGNORECASE):
                            suspicious_scripts.append(script)
                            break
            analysis['phishing_indicators']['suspicious_scripts'] = len(suspicious_scripts)

            # 4. Анализ внешних ресурсов
            domain = urlparse(url).netloc
            for tag in soup.find_all(['img', 'script', 'link', 'iframe']):
                src = tag.get('src') or tag.get('href')
                if src and domain not in src:
                    analysis['phishing_indicators']['external_resources'].append(src[:200])

            # Эвристические правила для фишинга
            if analysis['phishing_indicators']['password_fields'] > 1:
                analysis['warnings'].append('Обнаружено несколько полей для ввода пароля')
                analysis['is_dangerous'] = True

            if analysis['phishing_indicators']['hidden_elements'] > 5:
                analysis['warnings'].append('Обнаружено много скрытых элементов')

            if analysis['phishing_indicators']['suspicious_scripts'] > 0:
                analysis['warnings'].append('Найдены подозрительные JavaScript-функции')

            # Расширенные проверки
            analysis['domain_checks'] = check_domain_and_ssl(url)
            analysis['content_analysis'] = analyze_content(soup)
            analysis['reputation'] = check_reputation(url)
            analysis['heuristics'] = heuristic_checks(url, driver.page_source)

            # Обновляем логику определения опасности
            if (analysis['reputation'].get('is_blacklisted', False) or
                    analysis['heuristics'].get('typosquatting', False) or
                    analysis['content_analysis'].get('fake_login_forms', 0) > 0):
                analysis['is_dangerous'] = True

            logger.info(
                f"Анализ завершен для {url}. "
                f"Найдено {len(analysis['warnings'])} предупреждений."
            )

        except Exception as e:
            logger.error(f"Ошибка при анализе страницы: {str(e)}", exc_info=True)
            analysis['warnings'].append(f'Ошибка анализа: {str(e)}')

        return analysis

    @staticmethod
    def calculate_safety_level(analysis: Dict[str, Any]) -> Tuple[str, str]:
        """
        Рассчитывает уровень безопасности на основе анализа.

        Args:
            analysis: Результаты анализа безопасности

        Returns:
            Tuple: (уровень безопасности, цветовой код)
        """
        score = 0

        # Положительные факторы
        if analysis['basic_checks']['has_ssl']:
            score += 1

        domain_age = analysis['domain_checks'].get('domain_age_days')
        if domain_age is not None:
            if domain_age > 365:
                score += 2
            elif domain_age > 30:
                score += 1

        # Отрицательные факторы
        if analysis['reputation'].get('is_blacklisted', False):
            score -= 3

        if analysis['heuristics'].get('typosquatting', False):
            score -= 2

        if analysis['content_analysis'].get('fake_login_forms', 0) > 0:
            score -= 2

        if analysis['heuristics'].get('brand_impersonation', False):
            score -= 1

        # Определение уровня с защитой от крайних значений
        final_score = max(min(score, 4), -3)

        if final_score >= 3:
            return "🟢 Безопасно", "green"
        elif 1 <= final_score < 3:
            return "🟡 Условно безопасно", "yellow"
        elif -1 <= final_score < 1:
            return "🟠 Рискованно", "orange"
        else:
            return "🔴 Опасность!", "red"