from veas.application import create_app


app, socketio, monitor = create_app()
monitor.start_background_threads()
