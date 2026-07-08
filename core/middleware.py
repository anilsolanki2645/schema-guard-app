import logging
import threading
from django.conf import settings
from core import db_impl
from core.apps import register_pipeline_cron, scheduler

logger = logging.getLogger("core_startup")

class StartupMiddleware:
    _initialized = False
    _lock = threading.Lock()

    def __init__(self, get_response):
        self.get_response = get_response
        self._initialize()

    def _initialize(self):
        with StartupMiddleware._lock:
            if not StartupMiddleware._initialized:
                StartupMiddleware._initialized = True
                logger.info("Running application startup checks...")
                try:
                    # Run database migrations automatically
                    from django.core.management import call_command
                    logger.info("Applying database migrations programmatically...")
                    call_command('migrate', interactive=False)

                    db_impl.init_db()
                    # Only start scheduler if in main thread/reloader main or in production
                    import os
                    if os.environ.get('RUN_MAIN') == 'true' or not settings.DEBUG:
                        if not scheduler.running:
                            scheduler.start()
                            logger.info("Background scheduler started in StartupMiddleware.")
                            for pipeline in db_impl.get_all_pipelines():
                                try:
                                    register_pipeline_cron(pipeline)
                                except Exception as e:
                                    logger.error(f"Could not register cron for {pipeline['id']}: {e}")
                        else:
                            logger.info("Background scheduler is already running.")
                except Exception as e:
                    logger.error(f"Error during startup initialization: {e}", exc_info=True)

    def __call__(self, request):
        return self.get_response(request)
