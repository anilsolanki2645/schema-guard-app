import os
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent

# Load env file
env_path = BASE_DIR / ".env"
if env_path.exists():
    load_dotenv(env_path)


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "django-insecure-dev-only-key-do-not-use-in-production"
    else:
        raise RuntimeError(
            "FATAL: SECRET_KEY environment variable is not set. "
            "Set a strong, unique SECRET_KEY before deploying to production."
        )

ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "*").split(",")

# Auto-detect Render's external hostname
RENDER_EXTERNAL_HOSTNAME = os.environ.get("RENDER_EXTERNAL_HOSTNAME")
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# CSRF trusted origins for production (e.g. "https://schema-guard.example.com")
CSRF_TRUSTED_ORIGINS = [
    origin.strip() for origin in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if origin.strip()
]
if RENDER_EXTERNAL_HOSTNAME:
    CSRF_TRUSTED_ORIGINS.append(f"https://{RENDER_EXTERNAL_HOSTNAME}")

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'core.middleware.StartupMiddleware',
]

try:
    import whitenoise
    MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')
except ImportError:
    pass


ROOT_URLCONF = 'urls'

SETTINGS_DIR = Path(__file__).resolve().parent

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [SETTINGS_DIR / 'core' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'wsgi.application'

import sys
IS_TESTING = 'test' in sys.argv or 'test_coverage' in sys.argv or any('load_test' in arg for arg in sys.argv)

if IS_TESTING:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db_test.sqlite3',
            'OPTIONS': {
                'timeout': 60,
            }
        }
    }
elif os.environ.get("USE_SQLITE", "false").lower() == "true":
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
            'OPTIONS': {
                'timeout': 60,
            }
        }
    }
elif os.environ.get("PGHOST"):
    pghost = os.environ.get("PGHOST")
    opts = {
        'sslmode': os.environ.get("PGSSLMODE", "require"),
    }
    # Resolve hostaddr to protect against local Windows DNS failures or timeouts
    hostaddr = os.environ.get("PGHOSTADDR")
    if not hostaddr and pghost and pghost not in ('localhost', '127.0.0.1'):
        try:
            import socket
            hostaddr = socket.gethostbyname(pghost)
        except Exception:
            if 'c-9.us-east-1.aws.neon.tech' in pghost:
                hostaddr = '52.45.105.76'
    if hostaddr:
        opts['hostaddr'] = hostaddr

    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get("PGDATABASE", "neondb"),
            'USER': os.environ.get("PGUSER", "neondb_owner"),
            'PASSWORD': os.environ.get("PGPASSWORD", ""),
            'HOST': pghost,
            'PORT': os.environ.get("PGPORT") or 5432,
            'CONN_MAX_AGE': 600,
            'CONN_HEALTH_CHECKS': True,
            'OPTIONS': opts,
        }
    }
else:
    db_url = os.environ.get("NEON_DB_CONNECTION_STRING") or os.environ.get("DB_CONNECTION_STRING")
    if db_url:
        clean_url = db_url.split("?", 1)[0]
        parsed = urlparse(clean_url)
        opts = {'sslmode': 'require'}
        hostaddr = os.environ.get("PGHOSTADDR")
        if not hostaddr and parsed.hostname and parsed.hostname not in ('localhost', '127.0.0.1'):
            try:
                import socket
                hostaddr = socket.gethostbyname(parsed.hostname)
            except Exception:
                if 'c-9.us-east-1.aws.neon.tech' in parsed.hostname:
                    hostaddr = '52.45.105.76'
        if hostaddr:
            opts['hostaddr'] = hostaddr

        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.postgresql',
                'NAME': parsed.path.lstrip('/'),
                'USER': parsed.username,
                'PASSWORD': parsed.password,
                'HOST': parsed.hostname,
                'PORT': parsed.port or 5432,
                'CONN_MAX_AGE': 600,
                'CONN_HEALTH_CHECKS': True,
                'OPTIONS': opts,
            }
        }
    else:
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': BASE_DIR / 'db.sqlite3',
            }
        }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATICFILES_DIRS = [
    SETTINGS_DIR / 'core' / 'static',
]
STATIC_ROOT = SETTINGS_DIR / 'staticfiles'

# Serve static files efficiently in production using WhiteNoise if installed
try:
    import whitenoise
    STORAGES = {
        "staticfiles": {
            "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
        },
    }
except ImportError:
    pass


DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Session security
if IS_TESTING:
    SESSION_ENGINE = 'django.contrib.sessions.backends.db'
else:
    SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
SESSION_COOKIE_AGE = int(os.environ.get("SESSION_COOKIE_AGE", "86400"))  # 24 hours default
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Email settings configured from env variables or fallback
RESEND_API_KEY = os.environ.get('RESEND_API_KEY')
RESEND_FROM_EMAIL = os.environ.get('RESEND_FROM_EMAIL', 'onboarding@resend.dev')

if RESEND_API_KEY:
    EMAIL_BACKEND = 'core.email_backend.ResendEmailBackend'
    DEFAULT_FROM_EMAIL = RESEND_FROM_EMAIL
else:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
    try:
        EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '587') or '587')
    except ValueError:
        EMAIL_PORT = 587
    
    EMAIL_USE_SSL = os.environ.get('EMAIL_USE_SSL', 'false').lower() == 'true'
    if EMAIL_USE_SSL:
        EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'false').lower() == 'true'
    else:
        EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'true').lower() == 'true'
        
    EMAIL_HOST_USER = os.environ.get('EMAIL_USER')
    EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_PASSWORD')
    DEFAULT_FROM_EMAIL = os.environ.get('EMAIL_FROM', EMAIL_HOST_USER)
    
    # Fallback to console email backend in development if credentials are not configured
    if not EMAIL_HOST_USER or not EMAIL_HOST_PASSWORD:
        EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

EMAIL_TIMEOUT = 5

# Security settings for production
if not DEBUG:
    SECURE_SSL_REDIRECT = os.environ.get("SECURE_SSL_REDIRECT", "true").lower() == "true"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
    CSRF_COOKIE_SECURE = os.environ.get("CSRF_COOKIE_SECURE", "true").lower() == "true"
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    
    # HSTS settings
    SECURE_HSTS_SECONDS = int(os.environ.get("SECURE_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = os.environ.get("SECURE_HSTS_INCLUDE_SUBDOMAINS", "true").lower() == "true"
    SECURE_HSTS_PRELOAD = os.environ.get("SECURE_HSTS_PRELOAD", "true").lower() == "true"

    # Enterprise Defense-in-depth headers
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_REFERRER_POLICY = 'same-origin'

# Stripe Billing Settings
STRIPE_PUBLIC_KEY = os.environ.get('STRIPE_PUBLIC_KEY', 'pk_test_placeholder')
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_placeholder')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', 'whsec_placeholder')
STRIPE_PRO_PRICE_ID = os.environ.get('STRIPE_PRO_PRICE_ID', 'price_pro_monthly')
STRIPE_ENTERPRISE_PRICE_ID = os.environ.get('STRIPE_ENTERPRISE_PRICE_ID', 'price_enterprise_monthly')

PLAN_QUOTAS = {
    'free': {'max_pipelines': 5, 'name': 'Developer (Free)'},
    'pro': {'max_pipelines': 50, 'name': 'Team Pro'},
    'enterprise': {'max_pipelines': 1000, 'name': 'Enterprise'},
}

# OAuth Settings (GitHub & Google)
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID', '')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET', '')
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'production': {
            'format': '[{asctime}] {levelname} {name}: {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'production',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO' if DEBUG else 'WARNING',
            'propagate': True,
        },
        'django.request': {
            'handlers': ['console'],
            'level': 'ERROR',
            'propagate': False,
        },
        'core_views': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}



