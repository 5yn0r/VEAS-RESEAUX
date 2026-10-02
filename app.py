import logging

import config
from moniwifi.application import create_app

logger = logging.getLogger(__name__)
app, socketio, monitor = create_app()


if __name__ == "__main__":
    if not config.DEBUG:
        raise SystemExit("Production startup uses Gunicorn. Run ./run.sh instead.")

    monitor.start_background_threads()
    logger.info("Starting development server on http://%s:%s", config.HOST, config.PORT)
    socketio.run(
        app,
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        log_output=False,
    )
