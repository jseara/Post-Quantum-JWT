"""Application behind the Sprint 2 transport proxy; run it with Gunicorn, not directly."""

from flask import Flask, jsonify, request


app = Flask(__name__)


@app.get("/health")
def health():
    """Report that the request arrived, and whether nginx forwarded it."""
    return jsonify(status="ok", proxied_by=request.headers.get("X-Proxied-By"))
