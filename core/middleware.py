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
                import sys
                is_testing = 'test' in sys.argv or 'test_coverage' in sys.argv
                
                if is_testing:
                    return

                try:
                    # Safely seed admin account if tables exist; do NOT run migrations or collectstatic here.
                    db_impl.init_db()

                    import os
                    enable_sched = os.environ.get('ENABLE_SCHEDULER', 'true').lower() == 'true'
                    # In development, only start scheduler on main reloader thread
                    is_main_dev = os.environ.get('RUN_MAIN') == 'true'
                    if enable_sched and (is_main_dev or not settings.DEBUG):
                        if not scheduler.running:
                            scheduler.start()
                            logger.info("Background scheduler initialized successfully.")
                            for pipeline in db_impl.get_all_pipelines(mask_credentials=False):
                                try:
                                    register_pipeline_cron(pipeline)
                                except Exception as e:
                                    logger.error(f"Could not register cron for {pipeline.get('id')}: {e}")
                        else:
                            logger.info("Background scheduler is already running.")
                except Exception as e:
                    logger.error(f"Error during startup initialization: {e}", exc_info=True)

    def __call__(self, request):
        return self.get_response(request)
