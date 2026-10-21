import os

bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"
workers = 1
threads = 64
worker_class = "gthread"
timeout = 120
keepalive = 35
accesslog = "-"
errorlog = "-"
preload_app = False
