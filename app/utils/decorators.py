from datetime import datetime
from functools import wraps

import jwt
from flask import (
    Response,
    abort,
    current_app,
    flash,
    redirect,
    request,
    session,
    url_for,
)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get("token")
        current_app.logger.debug(
            f"Checking token: {token[:10]}..." if isinstance(token, str) else token
        )

        if not token:
            current_app.logger.info("No token found in session, redirecting to login")
            session.clear()
            return redirect(url_for("auth.login", next=request.url))

        try:
            if not isinstance(token, str):
                current_app.logger.info("Invalid token type, redirecting to login")
                session.clear()
                return redirect(url_for("auth.login", next=request.url))

            try:
                # Verify the token signature and decode
                current_app.logger.debug("Verifying token...")
                decoded = jwt.decode(
                    token,
                    current_app.config["SECRET_KEY"],
                    algorithms=["HS256"],
                    options={"verify_exp": False},
                )
                current_app.logger.debug(f"Token decoded successfully: {decoded}")

                exp = decoded.get("exp")
                current_time = datetime.utcnow().timestamp()
                current_app.logger.debug(f"Checking expiry: exp={exp}, current={current_time}")

                if exp is None:
                    current_app.logger.info("Token has no expiry")
                    session.clear()
                    return redirect(url_for("auth.login", next=request.url))

                if current_time >= float(exp):
                    current_app.logger.info(f"Token expired (exp: {exp}, current: {current_time})")
                    session.clear()
                    return redirect(url_for("auth.login", next=request.url))

                current_app.logger.debug("Token is valid and not expired")
                return f(*args, **kwargs)

            except jwt.InvalidSignatureError as e:
                current_app.logger.info(f"Invalid token signature: {str(e)}")
                session.clear()
                return redirect(url_for("auth.login", next=request.url))

            except jwt.InvalidTokenError as e:
                current_app.logger.info(f"Invalid token format: {str(e)}")
                session.clear()
                return redirect(url_for("auth.login", next=request.url))

        except Exception as e:
            current_app.logger.error(f"Unexpected error in login_required: {str(e)}")
            session.clear()
            return redirect(url_for("auth.login", next=request.url))

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin access required.")
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function
