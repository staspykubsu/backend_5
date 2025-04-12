#!/usr/bin/env python3

import cgi
import http.cookies
import re
import pymysql
from datetime import datetime, timedelta
import os
import hashlib
import secrets
import json
import base64
import hmac

def create_connection():
    try:
        return pymysql.connect(
            host='158.160.171.237',
            user='u68593',
            password='9258357',
            database='web_db',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
    except pymysql.Error as e:
        print(f"Ошибка подключения к базе данных: {e}")
        return None

def validate_form(data):
    errors = {}
    patterns = {
        'last_name': r'^[А-Яа-яЁё]+$',
        'first_name': r'^[А-Яа-яЁё]+$',
        'patronymic': r'^[А-Яа-яЁё]*$',
        'phone': r'^\+?\d{10,15}$',
        'email': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
        'birthdate': r'^\d{4}-\d{2}-\d{2}$',
        'bio': r'^.{10,}$'
    }
    messages = {
        'last_name': "Фамилия должна содержать только буквы кириллицы.",
        'first_name': "Имя должно содержать только буквы кириллицы.",
        'patronymic': "Отчество должно содержать только буквы кириллицы (если указано).",
        'phone': "Телефон должен быть длиной от 10 до 15 цифр и может начинаться с '+'",
        'email': "Некорректный email. Пример: example@domain.com",
        'birthdate': "Дата рождения должна быть в формате YYYY-MM-DD.",
        'bio': "Биография должна содержать не менее 10 символов."
    }

    for field, pattern in patterns.items():
        if field in data and not re.match(pattern, data[field]):
            errors[field] = messages[field]

    if 'gender' not in data or data['gender'] not in ['male', 'female']:
        errors['gender'] = "Выберите пол."

    if 'languages' not in data or not data['languages']:
        errors['languages'] = "Выберите хотя бы один язык программирования."

    if 'contract' not in data or not data['contract']:
        errors['contract'] = "Необходимо подтвердить ознакомление с контрактом."

    return errors

def generate_html_form(data, errors, is_authenticated=False, credentials=None):
    html = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Форма</title>
        <link rel="stylesheet" href="styles.css">
    </head>
    <body>
        {login_section}
        <form action="" method="POST">
            {auth_field}
            <label for="last_name">Фамилия:</label>
            <input type="text" id="last_name" name="last_name" maxlength="50" required
                   value="{last_name}" class="{last_name_error_class}" {readonly}>
            <span class="error-message">{last_name_error}</span><br>

            <label for="first_name">Имя:</label>
            <input type="text" id="first_name" name="first_name" maxlength="50" required
                   value="{first_name}" class="{first_name_error_class}" {readonly}>
            <span class="error-message">{first_name_error}</span><br>

            <label for="patronymic">Отчество:</label>
            <input type="text" id="patronymic" name="patronymic" maxlength="50"
                   value="{patronymic}" class="{patronymic_error_class}" {readonly}>
            <span class="error-message">{patronymic_error}</span><br>

            <label for="phone">Телефон:</label>
            <input type="tel" id="phone" name="phone" required
                   value="{phone}" class="{phone_error_class}" {readonly}>
            <span class="error-message">{phone_error}</span><br>

            <label for="email">E-mail:</label>
            <input type="email" id="email" name="email" required
                   value="{email}" class="{email_error_class}" {readonly}>
            <span class="error-message">{email_error}</span><br>

            <label for="birthdate">Дата рождения:</label>
            <input type="date" id="birthdate" name="birthdate" required
                   value="{birthdate}" class="{birthdate_error_class}" {readonly}>
            <span class="error-message">{birthdate_error}</span><br>

            <label>Пол:</label>
            <label for="male">Мужской</label>
            <input type="radio" id="male" name="gender" value="male" required {male_checked} {disabled}>
            <label for="female">Женский</label>
            <input type="radio" id="female" name="gender" value="female" required {female_checked} {disabled}>
            <span class="error-message">{gender_error}</span><br>

            <label for="languages">Любимый язык программирования:</label>
            <select id="languages" name="languages[]" multiple required {disabled}>
                <option value="Pascal" {pascal_selected}>Pascal</option>
                <option value="C" {c_selected}>C</option>
                <option value="C++" {cpp_selected}>C++</option>
                <option value="JavaScript" {javascript_selected}>JavaScript</option>
                <option value="PHP" {php_selected}>PHP</option>
                <option value="Python" {python_selected}>Python</option>
                <option value="Java" {java_selected}>Java</option>
                <option value="Haskel" {haskel_selected}>Haskel</option>
                <option value="Clojure" {clojure_selected}>Clojure</option>
                <option value="Prolog" {prolog_selected}>Prolog</option>
                <option value="Scala" {scala_selected}>Scala</option>
                <option value="Go" {go_selected}>Go</option>
            </select>
            <span class="error-message">{languages_error}</span><br>

            <label for="bio">Биография:</label>
            <textarea id="bio" name="bio" rows="4" required class="{bio_error_class}" {readonly}>{bio}</textarea>
            <span class="error-message">{bio_error}</span><br>

            <label for="contract">С контрактом ознакомлен(а)</label>
            <input type="checkbox" id="contract" name="contract" required {contract_checked} {disabled}>
            <span class="error-message">{contract_error}</span><br>

            <button type="submit" {disabled}>Сохранить</button>
        </form>
    </body>
    </html>
    """

    login_section = ""
    if is_authenticated:
        login_section = f"""
        <div class="auth-info">
            <p>Вы вошли как пользователь {data.get('username', '')}</p>
            <form action="" method="POST">
                <input type="hidden" name="logout" value="1">
                <button type="submit">Выйти</button>
            </form>
        </div>
        """
    else:
        login_section = """
        <div class="login-form">
            <form action="" method="POST">
                <h3>Вход</h3>
                <label for="username">Логин:</label>
                <input type="text" id="username" name="username" required><br>
                <label for="password">Пароль:</label>
                <input type="password" id="password" name="password" required><br>
                <button type="submit" name="login">Войти</button>
            </form>
        </div>
        """

    readonly = "readonly" if is_authenticated and not data.get('edit_mode', False) else ""
    disabled = "disabled" if is_authenticated and not data.get('edit_mode', False) else ""
    auth_field = "<input type='hidden' name='auth_token' value='{auth_token}'>" if is_authenticated else ""
    
    if credentials:
        login_section += f"""
        <div class="credentials">
            <h3>Ваши учетные данные (сохраните их):</h3>
            <p>Логин: {credentials['username']}</p>
            <p>Пароль: {credentials['password']}</p>
        </div>
        """

    context = {
        'login_section': login_section,
        'auth_field': auth_field.format(auth_token=data.get('auth_token', '')) if is_authenticated else '',
        'last_name': data.get('last_name', ''),
        'first_name': data.get('first_name', ''),
        'patronymic': data.get('patronymic', ''),
        'phone': data.get('phone', ''),
        'email': data.get('email', ''),
        'birthdate': data.get('birthdate', ''),
        'male_checked': 'checked' if data.get('gender') == 'male' else '',
        'female_checked': 'checked' if data.get('gender') == 'female' else '',
        'pascal_selected': 'selected' if 'Pascal' in data.get('languages', []) else '',
        'c_selected': 'selected' if 'C' in data.get('languages', []) else '',
        'cpp_selected': 'selected' if 'C++' in data.get('languages', []) else '',
        'javascript_selected': 'selected' if 'JavaScript' in data.get('languages', []) else '',
        'php_selected': 'selected' if 'PHP' in data.get('languages', []) else '',
        'python_selected': 'selected' if 'Python' in data.get('languages', []) else '',
        'java_selected': 'selected' if 'Java' in data.get('languages', []) else '',
        'haskel_selected': 'selected' if 'Haskel' in data.get('languages', []) else '',
        'clojure_selected': 'selected' if 'Clojure' in data.get('languages', []) else '',
        'prolog_selected': 'selected' if 'Prolog' in data.get('languages', []) else '',
        'scala_selected': 'selected' if 'Scala' in data.get('languages', []) else '',
        'go_selected': 'selected' if 'Go' in data.get('languages', []) else '',
        'bio': data.get('bio', ''),
        'contract_checked': 'checked' if data.get('contract') else '',
        'last_name_error': errors.get('last_name', ''),
        'first_name_error': errors.get('first_name', ''),
        'patronymic_error': errors.get('patronymic', ''),
        'phone_error': errors.get('phone', ''),
        'email_error': errors.get('email', ''),
        'birthdate_error': errors.get('birthdate', ''),
        'gender_error': errors.get('gender', ''),
        'languages_error': errors.get('languages', ''),
        'bio_error': errors.get('bio', ''),
        'contract_error': errors.get('contract', ''),
        'last_name_error_class': 'error' if 'last_name' in errors else '',
        'first_name_error_class': 'error' if 'first_name' in errors else '',
        'patronymic_error_class': 'error' if 'patronymic' in errors else '',
        'phone_error_class': 'error' if 'phone' in errors else '',
        'email_error_class': 'error' if 'email' in errors else '',
        'birthdate_error_class': 'error' if 'birthdate' in errors else '',
        'bio_error_class': 'error' if 'bio' in errors else '',
        'readonly': readonly,
        'disabled': disabled
    }

    return html.format(**context)

def generate_credentials():
    username = secrets.token_hex(8)
    password = secrets.token_hex(12)
    return {'username': username, 'password': password}

def hash_password(password):
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}:{key.hex()}"

def verify_password(stored_password, provided_password):
    salt, key = stored_password.split(':')
    new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return hmac.compare_digest(key, new_key.hex())

def create_session_token(user_id):
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload = {'user_id': user_id, 'exp': datetime.now() + timedelta(days=1)}
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    signature = hmac.new(b'secret_key', f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def verify_session_token(token):
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        
        # Add padding back if needed
        header_b64 += '=' * (4 - len(header_b64) % 4)
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        signature_b64 += '=' * (4 - len(signature_b64) % 4)
        
        header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        
        expected_signature = hmac.new(b'secret_key', f"{header_b64[:-2]}.{payload_b64[:-2]}".encode(), hashlib.sha256).digest()
        provided_signature = base64.urlsafe_b64decode(signature_b64)
        
        if not hmac.compare_digest(expected_signature, provided_signature):
            return None
            
        if datetime.strptime(payload['exp'], '%Y-%m-%d %H:%M:%S.%f') < datetime.now():
            return None
            
        return payload['user_id']
    except:
        return None

def insert_user_data(connection, data):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            INSERT INTO applications (last_name, first_name, patronymic, phone, email, birthdate, gender, bio, contract)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['last_name'], data['first_name'], data['patronymic'],
            data['phone'], data['email'], data['birthdate'],
            data['gender'], data['bio'], data['contract']
        ))
        
        application_id = cursor.lastrowid

        language_ids = {
            'Pascal': 1,
            'C': 2,
            'C++': 3,
            'JavaScript': 4,
            'PHP': 5,
            'Python': 6,
            'Java': 7,
            'Haskel': 8,
            'Clojure': 9,
            'Prolog': 10,
            'Scala': 11,
            'Go': 12
        }

        for language in data['languages']:
            language_id = language_ids.get(language)
            if language_id:
                cursor.execute("""
                    INSERT INTO application_languages (application_id, language_id)
                    VALUES (%s, %s)
                """, (application_id, language_id))
        
        # Generate credentials
        credentials = generate_credentials()
        hashed_password = hash_password(credentials['password'])
        
        cursor.execute("""
            INSERT INTO user_credentials (application_id, username, password_hash)
            VALUES (%s, %s, %s)
        """, (application_id, credentials['username'], hashed_password))
        
        connection.commit()
        return credentials
    except pymysql.Error as e:
        print(f"Ошибка при вставке данных: {e}")
        return None
    finally:
        cursor.close()

def update_user_data(connection, user_id, data):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            UPDATE applications 
            SET last_name = %s, first_name = %s, patronymic = %s, 
                phone = %s, email = %s, birthdate = %s, 
                gender = %s, bio = %s, contract = %s
            WHERE id = %s
        """, (
            data['last_name'], data['first_name'], data['patronymic'],
            data['phone'], data['email'], data['birthdate'],
            data['gender'], data['bio'], data['contract'], user_id
        ))
        
        # Delete old languages
        cursor.execute("DELETE FROM application_languages WHERE application_id = %s", (user_id,))
        
        # Insert new languages
        language_ids = {
            'Pascal': 1,
            'C': 2,
            'C++': 3,
            'JavaScript': 4,
            'PHP': 5,
            'Python': 6,
            'Java': 7,
            'Haskel': 8,
            'Clojure': 9,
            'Prolog': 10,
            'Scala': 11,
            'Go': 12
        }

        for language in data['languages']:
            language_id = language_ids.get(language)
            if language_id:
                cursor.execute("""
                    INSERT INTO application_languages (application_id, language_id)
                    VALUES (%s, %s)
                """, (user_id, language_id))
        
        connection.commit()
        return True
    except pymysql.Error as e:
        print(f"Ошибка при обновлении данных: {e}")
        return False
    finally:
        cursor.close()

def get_user_data(connection, user_id):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT a.*, GROUP_CONCAT(l.name) as languages
            FROM applications a
            LEFT JOIN application_languages al ON a.id = al.application_id
            LEFT JOIN languages l ON al.language_id = l.id
            WHERE a.id = %s
            GROUP BY a.id
        """, (user_id,))
        
        result = cursor.fetchone()
        if not result:
            return None
            
        data = {
            'last_name': result['last_name'],
            'first_name': result['first_name'],
            'patronymic': result['patronymic'],
            'phone': result['phone'],
            'email': result['email'],
            'birthdate': result['birthdate'],
            'gender': result['gender'],
            'languages': result['languages'].split(',') if result['languages'] else [],
            'bio': result['bio'],
            'contract': result['contract'],
            'username': result.get('username', '')
        }
        
        return data
    except pymysql.Error as e:
        print(f"Ошибка при получении данных пользователя: {e}")
        return None
    finally:
        cursor.close()

def authenticate_user(connection, username, password):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT uc.application_id, uc.password_hash, a.id
            FROM user_credentials uc
            JOIN applications a ON uc.application_id = a.id
            WHERE uc.username = %s
        """, (username,))
        
        result = cursor.fetchone()
        if not result:
            return None
            
        if verify_password(result['password_hash'], password):
            return result['application_id']
        return None
    except pymysql.Error as e:
        print(f"Ошибка при аутентификации: {e}")
        return None
    finally:
        cursor.close()

if __name__ == "__main__":
    cookie = http.cookies.SimpleCookie()
    cookie.load(os.environ.get('HTTP_COOKIE', ''))
    
    form = cgi.FieldStorage()
    request_method = os.environ.get('REQUEST_METHOD', '')
    
    # Check for logout
    if 'logout' in form:
        print("Content-Type: text/html; charset=utf-8")
        print("Set-Cookie: auth_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/")
        print("\n")
        print("<h1>Вы успешно вышли</h1>")
        print("<a href=''>Вернуться к форме</a>")
        exit()
    
    # Check for authentication
    auth_token = form.getvalue('auth_token', cookie.get('auth_token', '').value if 'auth_token' in cookie else '')
    user_id = verify_session_token(auth_token) if auth_token else None
    is_authenticated = user_id is not None
    
    # Handle login
    if 'login' in form:
        username = form.getvalue('username', '').strip()
        password = form.getvalue('password', '').strip()
        
        connection = create_connection()
        if connection:
            user_id = authenticate_user(connection, username, password)
            if user_id:
                auth_token = create_session_token(user_id)
                cookie['auth_token'] = auth_token
                cookie['auth_token']['path'] = '/'
                cookie['auth_token']['expires'] = (datetime.now() + timedelta(days=1)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                is_authenticated = True
            connection.close()
    
    data = {
        'last_name': form.getvalue('last_name', '').strip(),
        'first_name': form.getvalue('first_name', '').strip(),
        'patronymic': form.getvalue('patronymic', '').strip(),
        'phone': form.getvalue('phone', '').strip(),
        'email': form.getvalue('email', '').strip(),
        'birthdate': form.getvalue('birthdate', '').strip(),
        'gender': form.getvalue('gender', '').strip(),
        'languages': form.getlist('languages[]'),
        'bio': form.getvalue('bio', '').strip(),
        'contract': 'contract' in form,
        'auth_token': auth_token,
        'edit_mode': 'edit' in form
    }
    
    # For authenticated users, load their data
    if is_authenticated and not any(data.values()):
        connection = create_connection()
        if connection:
            user_data = get_user_data(connection, user_id)
            if user_data:
                data.update(user_data)
            connection.close()
    
    # For non-authenticated users, load from cookies
    if not is_authenticated and not any(data.values()):
        for field in data.keys():
            if field in cookie:
                data[field] = cookie[field].value
    
    if request_method == 'POST':
        # Handle form submission
        if is_authenticated and not data['edit_mode']:
            # Toggle edit mode
            data['edit_mode'] = True
            print("Content-Type: text/html; charset=utf-8")
            print("\n")
            print(generate_html_form(data, {}, is_authenticated=True))
            exit()
        
        errors = validate_form(data)
        
        if errors:
            for field, message in errors.items():
                cookie[field + '_error'] = message
                cookie[field + '_error']['path'] = '/'
                cookie[field + '_error']['expires'] = 0

            print("Content-Type: text/html; charset=utf-8")
            print(cookie.output())
            print("\n")
            print(generate_html_form(data, errors, is_authenticated))
        else:
            for field in data.keys():
                if f'{field}_error' in cookie:
                    del cookie[f'{field}_error']

            connection = create_connection()
            if connection:
                if is_authenticated:
                    # Update existing data
                    success = update_user_data(connection, user_id, data)
                    if success:
                        data['edit_mode'] = False
                        message = "<h1>Данные успешно обновлены</h1>"
                    else:
                        message = "<h1>Ошибка при обновлении данных</h1>"
                else:
                    # Insert new data
                    credentials = insert_user_data(connection, data)
                    if credentials:
                        for field, value in data.items():
                            cookie[field] = value
                            cookie[field]['path'] = '/'
                            cookie[field]['expires'] = (datetime.now() + timedelta(days=365)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                        message = "<h1>Данные успешно сохранены</h1>"
                    else:
                        message = "<h1>Ошибка при сохранении данных</h1>"
                connection.close()
            
            print("Content-Type: text/html; charset=utf-8")
            if is_authenticated:
                print(cookie.output())
            else:
                if credentials:
                    print(cookie.output())
            print("\n")
            print(message)
            if not is_authenticated and credentials:
                print(generate_html_form(data, {}, credentials=credentials))
    else:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print(generate_html_form(data, {}, is_authenticated))
